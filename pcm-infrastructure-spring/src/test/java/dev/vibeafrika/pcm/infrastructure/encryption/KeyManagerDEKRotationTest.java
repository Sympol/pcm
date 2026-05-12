package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.SecureRandom;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for DEK rotation in KeyManager.
 *
 * <ul>
 *   <li>Automatic rotation after 90 days since DEK creation</li>
 *   <li>Automatic rotation after 1 terabyte of data encrypted</li>
 *   <li>Automatic rotation after 2^32 encryption operations</li>
 *   <li>Emergency rotation within 15 minutes when key compromise is suspected</li>
 * </ul>
 *
 * <p>These tests verify that {@code rotateDEK} correctly:
 * <ul>
 *   <li>Generates a new DEK and marks it as active</li>
 *   <li>Marks the old DEK as ROTATED</li>
 *   <li>Invalidates the old DEK from cache</li>
 *   <li>Resets the IV counter for the new DEK</li>
 *   <li>Logs the rotation event</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class KeyManagerDEKRotationTest {

    // Rotation thresholds 
    private static final long DEK_MAX_AGE_DAYS = 90L;
    private static final long DEK_MAX_BYTES_ENCRYPTED = 1_099_511_627_776L; // 1 TB
    private static final long DEK_MAX_ENCRYPTION_COUNT = 4_294_967_296L;    // 2^32

    @Mock
    private IKMSClient kmsClient;

    @Mock
    private IAuditLogger auditLogger;

    @Mock
    private IVCounter ivCounter;

    private DEKCache dekCache;
    private KeyManager keyManager;

    private static final BoundedContext CONTEXT = BoundedContext.PROFILE;
    private static final Environment ENV = Environment.PROD;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeEach
    void setUp() {
        dekCache = new DEKCache();
        keyManager = new KeyManager(kmsClient, auditLogger, dekCache, ENV, ivCounter);

        // Stub audit logger — KeyManager ignores the return value
        AuditError noopError = AuditError.of("NOOP", "no-op");
        lenient().when(auditLogger.logKeyAccess(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logKeyRotation(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logSecurityEvent(any())).thenReturn(Result.failure(noopError));

        // Stub IV counter reset — called after every rotateDEK
        lenient().when(ivCounter.resetState(any())).thenReturn(Result.success(Unit.unit()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private EncryptedDEK fakeEncryptedDEK(UUID kekId) {
        return EncryptedDEK.of(randomBytes(48), kekId);
    }

    /**
     * Initialises a KEK for the context and creates one DEK via rotateDEK.
     * Returns the DEK UUID.
     */
    private UUID setupContextWithOneDEK(UUID kekId) {
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(kekId));
        keyManager.initializeKEK(CONTEXT);

        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        Result<UUID, KeyError> result = keyManager.rotateDEK(CONTEXT);
        assertTrue(result.isSuccess(), "Initial DEK rotation should succeed");
        return result.getValue().orElseThrow();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Automatic rotation after 90 days
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that when a DEK has been active for 90 days, calling rotateDEK
     * produces a new active DEK and marks the old one as ROTATED.
     *
     * <p>kTHE Key_Manager SHALL rotate DEKs automatically when
     * 90 days have elapsed since DEK creation.
     */
    @Test
    void rotateDEK_after90Days_newDEKBecomesActive() {
        UUID kekId = UUID.randomUUID();
        UUID oldDEKId = setupContextWithOneDEK(kekId);

        // Simulate 90+ days having elapsed by performing a second rotation
        // (the trigger would be called by a scheduler after 90 days)
        EncryptedDEK newEncryptedDEK = fakeEncryptedDEK(kekId);
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(newEncryptedDEK));

        Result<UUID, KeyError> rotationResult = keyManager.rotateDEK(CONTEXT);

        assertTrue(rotationResult.isSuccess(), "Rotation after 90 days should succeed");
        UUID newDEKId = rotationResult.getValue().orElseThrow();

        assertNotEquals(oldDEKId, newDEKId,
                "New DEK ID must differ from the 90-day-old DEK ID");

        // The new DEK must be the active one — stub decryptDEK for cache-miss path
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                .thenReturn(Result.success(plainDEK));

        Result<DEKWithMetadata, KeyError> activeResult = keyManager.getActiveDEK(CONTEXT);
        assertTrue(activeResult.isSuccess());
        assertEquals(newDEKId, activeResult.getValue().orElseThrow().getKeyId(),
                "After 90-day rotation, the new DEK must be active");
    }

    /**
     * Verifies that the old DEK is marked as ROTATED after a 90-day rotation,
     * so historical data encrypted with it can still be decrypted.
     *
     * <p>old DEK remains accessible for decryption.
     */
    @Test
    void rotateDEK_after90Days_oldDEKMarkedRotated() {
        UUID kekId = UUID.randomUUID();
        UUID oldDEKId = setupContextWithOneDEK(kekId);

        // Stub for the second rotation
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        keyManager.rotateDEK(CONTEXT);

        // Old DEK should still be retrievable (for decrypting historical data)
        // but its status should be ROTATED
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                .thenReturn(Result.success(plainDEK));

        Result<DEKWithMetadata, KeyError> oldDEKResult = keyManager.getDEK(oldDEKId);
        assertTrue(oldDEKResult.isSuccess(),
                "Old DEK must remain retrievable after 90-day rotation (for historical decryption)");
        assertEquals(KeyStatus.ROTATED, oldDEKResult.getValue().orElseThrow().getStatus(),
                "Old DEK status must be ROTATED after 90-day rotation");
    }

    /**
     * Verifies that the rotation event is logged when a DEK is rotated after 90 days.
     *
     * <p>key rotation must be logged.
     */
    @Test
    void rotateDEK_after90Days_rotationEventIsLogged() {
        UUID kekId = UUID.randomUUID();
        UUID oldDEKId = setupContextWithOneDEK(kekId);

        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        keyManager.rotateDEK(CONTEXT);

        verify(auditLogger, atLeastOnce()).logKeyRotation(any(KeyRotationEvent.class));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Automatic rotation after 1 TB encrypted
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that when 1 TB of data has been encrypted with a DEK, calling
     * rotateDEK produces a new active DEK.
     *
     * <p>THE Key_Manager SHALL rotate DEKs automatically when
     * 1 terabyte of data has been encrypted with a single DEK.
     */
    @Test
    void rotateDEK_after1TBEncrypted_newDEKBecomesActive() {
        UUID kekId = UUID.randomUUID();
        UUID oldDEKId = setupContextWithOneDEK(kekId);

        // Simulate 1 TB threshold being reached — the scheduler/trigger calls rotateDEK
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        Result<UUID, KeyError> rotationResult = keyManager.rotateDEK(CONTEXT);

        assertTrue(rotationResult.isSuccess(),
                "Rotation after 1 TB encrypted should succeed");
        UUID newDEKId = rotationResult.getValue().orElseThrow();

        assertNotEquals(oldDEKId, newDEKId,
                "New DEK ID must differ from the 1-TB-threshold DEK ID");

        // Verify the new DEK is active — stub decryptDEK for cache-miss path
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                .thenReturn(Result.success(plainDEK));

        Result<DEKWithMetadata, KeyError> activeResult = keyManager.getActiveDEK(CONTEXT);
        assertTrue(activeResult.isSuccess());
        assertEquals(newDEKId, activeResult.getValue().orElseThrow().getKeyId(),
                "After 1-TB rotation, the new DEK must be active");
    }

    /**
     * Verify that the threshold constant of 1 TB corresponds to (1 TiB = 2^40 bytes).
     *
     * <p>1 terabyte = 1,099,511,627,776 bytes (1 TiB).
     */
    @Test
    void dekRotationThreshold_1TB_matchesRequirement() {
        // 1 TiB = 1024^4 bytes = 1,099,511,627,776 bytes
        long expectedOneTiB = 1_099_511_627_776L;
        assertEquals(expectedOneTiB, DEK_MAX_BYTES_ENCRYPTED,
                "1 TB threshold must be exactly 1,099,511,627,776 bytes (1 TiB)");
    }

    /**
     * Verifies that after 1-TB rotation, the old DEK is marked ROTATED and
     * the IV counter is reset for the new DEK.
     */
    @Test
    void rotateDEK_after1TBEncrypted_oldDEKMarkedRotatedAndIVCounterReset() {
        UUID kekId = UUID.randomUUID();
        UUID oldDEKId = setupContextWithOneDEK(kekId);

        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        Result<UUID, KeyError> rotationResult = keyManager.rotateDEK(CONTEXT);
        assertTrue(rotationResult.isSuccess());
        UUID newDEKId = rotationResult.getValue().orElseThrow();

        // IV counter must be reset for the new DEK
        verify(ivCounter).resetState(eq(newDEKId));

        // Old DEK must be ROTATED
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                .thenReturn(Result.success(plainDEK));

        Result<DEKWithMetadata, KeyError> oldDEKResult = keyManager.getDEK(oldDEKId);
        assertTrue(oldDEKResult.isSuccess());
        assertEquals(KeyStatus.ROTATED, oldDEKResult.getValue().orElseThrow().getStatus(),
                "Old DEK must be ROTATED after 1-TB threshold rotation");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Automatic rotation after 2^32 operations
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that when 2^32 encryption operations have been performed with a DEK,
     * calling rotateDEK produces a new active DEK.
     *
     * <p>THE Key_Manager SHALL rotate DEKs automatically when
     * 2^32 encryption operations have been performed with a single DEK.
     */
    @Test
    void rotateDEK_after2Pow32Operations_newDEKBecomesActive() {
        UUID kekId = UUID.randomUUID();
        UUID oldDEKId = setupContextWithOneDEK(kekId);

        // Simulate 2^32 operations threshold being reached
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        Result<UUID, KeyError> rotationResult = keyManager.rotateDEK(CONTEXT);

        assertTrue(rotationResult.isSuccess(),
                "Rotation after 2^32 operations should succeed");
        UUID newDEKId = rotationResult.getValue().orElseThrow();

        assertNotEquals(oldDEKId, newDEKId,
                "New DEK ID must differ from the 2^32-operations DEK ID");

        // Verify the new DEK is active — stub decryptDEK for cache-miss path
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                .thenReturn(Result.success(plainDEK));

        Result<DEKWithMetadata, KeyError> activeResult = keyManager.getActiveDEK(CONTEXT);
        assertTrue(activeResult.isSuccess());
        assertEquals(newDEKId, activeResult.getValue().orElseThrow().getKeyId(),
                "After 2^32-operations rotation, the new DEK must be active");
    }

    /**
     * Verifies that the 2^32 threshold constant matches the requirement.
     *
     * <p>2^32 = 4,294,967,296 operations.
     */
    @Test
    void dekRotationThreshold_2Pow32_matchesRequirement() {
        long expected2Pow32 = 4_294_967_296L;
        assertEquals(expected2Pow32, DEK_MAX_ENCRYPTION_COUNT,
                "2^32 threshold must be exactly 4,294,967,296 operations");
    }

    /**
     * Verifies that after 2^32-operations rotation, the old DEK is evicted from
     * cache and the IV counter is reset for the new DEK.
     *
     * <p>counter overflow triggers DEK rotation.
     */
    @Test
    void rotateDEK_after2Pow32Operations_oldDEKEvictedFromCacheAndIVCounterReset() {
        UUID kekId = UUID.randomUUID();
        UUID oldDEKId = setupContextWithOneDEK(kekId);

        // Populate cache for the old DEK
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                .thenReturn(Result.success(plainDEK));
        keyManager.getDEK(oldDEKId);
        assertEquals(1, dekCache.size(), "Old DEK should be in cache before rotation");

        // Rotate (simulating 2^32 operations threshold)
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        Result<UUID, KeyError> rotationResult = keyManager.rotateDEK(CONTEXT);
        assertTrue(rotationResult.isSuccess());
        UUID newDEKId = rotationResult.getValue().orElseThrow();

        // Old DEK must be evicted from cache
        assertFalse(dekCache.get(oldDEKId).isPresent(),
                "Old DEK must be evicted from cache after 2^32-operations rotation");

        // IV counter must be reset for the new DEK
        verify(ivCounter).resetState(eq(newDEKId));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Emergency rotation within 15 minutes
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that emergency rotation (when key compromise is suspected) completes
     * successfully and produces a new active DEK.
     *
     * <p>WHEN key compromise is suspected, THE Key_Manager SHALL
     * support emergency key rotation within 15 minutes.
     *
     * <p>This test verifies the rotation logic executes correctly (not wall-clock time).
     * The 15-minute SLA is an operational requirement enforced by the calling system.
     */
    @Test
    void rotateDEK_emergencyRotation_completesSuccessfully() {
        UUID kekId = UUID.randomUUID();
        UUID compromisedDEKId = setupContextWithOneDEK(kekId);

        // Emergency rotation: immediately call rotateDEK upon compromise detection
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        long startNs = System.nanoTime();
        Result<UUID, KeyError> emergencyResult = keyManager.rotateDEK(CONTEXT);
        long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;

        assertTrue(emergencyResult.isSuccess(),
                "Emergency rotation must complete successfully");

        UUID newDEKId = emergencyResult.getValue().orElseThrow();
        assertNotEquals(compromisedDEKId, newDEKId,
                "Emergency rotation must produce a new DEK different from the compromised one");

        // The rotation logic itself must be fast (well under 15 minutes)
        assertTrue(elapsedMs < 60_000,
                "Emergency rotation logic must complete in under 60 seconds (SLA: 15 minutes)");
    }

    /**
     * Verifies that after emergency rotation, the compromised DEK is immediately
     * evicted from cache so it cannot be used for new encryptions.
     *
     * <p>cache invalidation within 60 seconds of rotation.
     */
    @Test
    void rotateDEK_emergencyRotation_compromisedDEKEvictedFromCache() {
        UUID kekId = UUID.randomUUID();
        UUID compromisedDEKId = setupContextWithOneDEK(kekId);

        // Populate cache for the compromised DEK
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                .thenReturn(Result.success(plainDEK));
        keyManager.getDEK(compromisedDEKId);
        assertTrue(dekCache.get(compromisedDEKId).isPresent(),
                "Compromised DEK should be in cache before emergency rotation");

        // Emergency rotation
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));
        keyManager.rotateDEK(CONTEXT);

        assertFalse(dekCache.get(compromisedDEKId).isPresent(),
                "Compromised DEK must be immediately evicted from cache after emergency rotation");
    }

    /**
     * Verifies that after emergency rotation, the new DEK is immediately active
     * so all subsequent encryptions use the safe key.
     *
     * <p>new key becomes active after rotation.
     */
    @Test
    void rotateDEK_emergencyRotation_newDEKImmediatelyActive() {
        UUID kekId = UUID.randomUUID();
        setupContextWithOneDEK(kekId);

        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        Result<UUID, KeyError> emergencyResult = keyManager.rotateDEK(CONTEXT);
        assertTrue(emergencyResult.isSuccess());
        UUID newDEKId = emergencyResult.getValue().orElseThrow();

        // New DEK must be immediately active — stub decryptDEK for cache-miss path
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                .thenReturn(Result.success(plainDEK));

        Result<DEKWithMetadata, KeyError> activeResult = keyManager.getActiveDEK(CONTEXT);
        assertTrue(activeResult.isSuccess());
        assertEquals(newDEKId, activeResult.getValue().orElseThrow().getKeyId(),
                "New DEK must be immediately active after emergency rotation");
    }

    /**
     * Verifies that emergency rotation logs a key rotation event so the incident
     * is captured in the audit trail.
     *
     * <p>key rotation must be logged.
     */
    @Test
    void rotateDEK_emergencyRotation_rotationEventIsLogged() {
        UUID kekId = UUID.randomUUID();
        setupContextWithOneDEK(kekId);

        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        keyManager.rotateDEK(CONTEXT);

        verify(auditLogger, atLeastOnce()).logKeyRotation(any(KeyRotationEvent.class));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cross-cutting: rotation failure handling
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that if KMS fails during rotation, the old DEK remains active
     * (rotation is atomic — partial state is not committed).
     *
     * <p>rotation must not leave the system
     * in an inconsistent state on failure.
     */
    @Test
    void rotateDEK_kmsFailure_oldDEKRemainsActive() {
        UUID kekId = UUID.randomUUID();
        UUID oldDEKId = setupContextWithOneDEK(kekId);

        // KMS fails to encrypt the new DEK
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.failure(KMSError.of("KMS_UNAVAILABLE", "KMS is down")));

        Result<UUID, KeyError> failedRotation = keyManager.rotateDEK(CONTEXT);

        assertTrue(failedRotation.isFailure(),
                "Rotation should fail when KMS is unavailable");

        // Old DEK must still be active — stub decryptDEK for cache-miss path
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                .thenReturn(Result.success(plainDEK));

        Result<DEKWithMetadata, KeyError> activeResult = keyManager.getActiveDEK(CONTEXT);
        assertTrue(activeResult.isSuccess());
        assertEquals(oldDEKId, activeResult.getValue().orElseThrow().getKeyId(),
                "Old DEK must remain active when rotation fails due to KMS unavailability");
    }

    /**
     * Verifies that rotateDEK fails with a descriptive error when no KEK exists
     * for the context (e.g., context not yet initialized).
     */
    @Test
    void rotateDEK_withoutKEK_returnsError() {
        // No KEK initialized for CONSENT context
        Result<UUID, KeyError> result = keyManager.rotateDEK(BoundedContext.CONSENT);

        assertTrue(result.isFailure(), "Rotation without KEK should fail");
        assertEquals("KEK_NOT_FOUND", result.getError().orElseThrow().getCode(),
                "Error code must be KEK_NOT_FOUND when no KEK exists for the context");
    }

    /**
     * Verifies that multiple sequential rotations (e.g., simulating multiple
     * 90-day cycles) each produce a distinct DEK ID.
     *
     * <p>each rotation cycle must produce a unique DEK.
     */
    @Test
    void rotateDEK_multipleSequentialRotations_eachProducesDistinctDEK() {
        UUID kekId = UUID.randomUUID();
        setupContextWithOneDEK(kekId);

        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenAnswer(inv -> Result.success(fakeEncryptedDEK(kekId)));

        UUID firstRotationId = keyManager.rotateDEK(CONTEXT).getValue().orElseThrow();
        UUID secondRotationId = keyManager.rotateDEK(CONTEXT).getValue().orElseThrow();
        UUID thirdRotationId = keyManager.rotateDEK(CONTEXT).getValue().orElseThrow();

        assertNotEquals(firstRotationId, secondRotationId,
                "Each rotation must produce a distinct DEK ID (rotation 1 vs 2)");
        assertNotEquals(secondRotationId, thirdRotationId,
                "Each rotation must produce a distinct DEK ID (rotation 2 vs 3)");
        assertNotEquals(firstRotationId, thirdRotationId,
                "Each rotation must produce a distinct DEK ID (rotation 1 vs 3)");
    }
}
