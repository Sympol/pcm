package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

/**
 * Unit tests for KEK rotation in KeyManager.
 *
 * <p>Validates: The Key_Manager SHALL rotate KEKs annually
 * or when required by compliance policies.
 *
 * <p>Tests cover:
 * <ul>
 *   <li>Annual KEK rotation - new KEK generated, DEKs re-encrypted, old KEK marked rotated</li>
 *   <li>KEK rotation with multiple DEKs - all DEKs re-encrypted with new KEK</li>
 *   <li>Cache invalidation after KEK rotation - all cached DEKs for context are evicted</li>
 *   <li>Decryption after KEK rotation - data encrypted before rotation is still decryptable</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class KeyManagerKEKRotationTest {

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

        // Stub audit logger to return success for all calls (KeyManager ignores return value)
        AuditError noopError = AuditError.of("NOOP", "no-op");
        lenient().when(auditLogger.logKeyAccess(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logKeyRotation(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logSecurityEvent(any())).thenReturn(Result.failure(noopError));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helper methods
    // ─────────────────────────────────────────────────────────────────────────

    private byte[] randomDEKBytes() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private EncryptedDEK fakeEncryptedDEK(UUID kekId) {
        byte[] ct = new byte[48];
        RANDOM.nextBytes(ct);
        return EncryptedDEK.of(ct, kekId);
    }

    /**
     * Initialises a KEK for the context and registers one DEK encrypted with it.
     * Returns the DEK UUID so callers can verify re-encryption.
     */
    private UUID setupContextWithOneDEK(UUID kekId, UUID dekId) {
        // KEK initialisation
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(kekId));
        keyManager.initializeKEK(CONTEXT);

        // DEK creation
        EncryptedDEK encryptedDEK = fakeEncryptedDEK(kekId);
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId))).thenReturn(Result.success(encryptedDEK));
        when(ivCounter.resetState(any())).thenReturn(Result.success(Unit.unit()));

        // rotateDEK stores the DEK in the metadata store and sets it as active
        Result<UUID, KeyError> rotateResult = keyManager.rotateDEK(CONTEXT);
        assertTrue(rotateResult.isSuccess(), "DEK rotation should succeed during setup");

        return rotateResult.getValue().orElseThrow();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Annual KEK rotation
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that rotateKEK generates a new KEK in KMS, re-encrypts all DEKs
     * with the new KEK, and marks the old KEK as rotated.
     */
    @Test
    void rotateKEK_generatesNewKEKAndReEncryptsDEKs() {
        UUID oldKEKId = UUID.randomUUID();
        UUID newKEKId = UUID.randomUUID();

        UUID dekId = setupContextWithOneDEK(oldKEKId, UUID.randomUUID());
        clearInvocations(kmsClient); // reset invocation counts after setup

        // Stub: new KEK generation
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(newKEKId));

        // Stub: decrypt DEK with old KEK, then re-encrypt with new KEK
        DEK plainDEK = DEK.of(randomDEKBytes());
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(oldKEKId)))
                .thenReturn(Result.success(plainDEK));
        EncryptedDEK reEncryptedDEK = fakeEncryptedDEK(newKEKId);
        when(kmsClient.encryptDEK(eq(plainDEK), eq(newKEKId)))
                .thenReturn(Result.success(reEncryptedDEK));

        // Act
        Result<UUID, KeyError> result = keyManager.rotateKEK(CONTEXT);

        // Assert: rotation succeeded and returned the new KEK ID
        assertTrue(result.isSuccess(), "KEK rotation should succeed");
        assertEquals(newKEKId, result.getValue().orElseThrow());

        // Assert: KMS was asked to generate a new KEK
        verify(kmsClient).generateKEK(CONTEXT, ENV);

        // Assert: the DEK was decrypted with the old KEK and re-encrypted with the new KEK
        verify(kmsClient).decryptDEK(any(EncryptedDEK.class), eq(oldKEKId));
        verify(kmsClient).encryptDEK(eq(plainDEK), eq(newKEKId));

        // Assert: a key-rotation audit event was logged
        ArgumentCaptor<KeyRotationEvent> rotationCaptor = ArgumentCaptor.forClass(KeyRotationEvent.class);
        verify(auditLogger, atLeastOnce()).logKeyRotation(rotationCaptor.capture());
        KeyRotationEvent rotationEvent = rotationCaptor.getAllValues().stream()
                .filter(e -> "KEK".equals(e.getKeyType()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No KEK rotation event logged"));
        assertEquals(oldKEKId, rotationEvent.getOldKeyId());
        assertEquals(newKEKId, rotationEvent.getNewKeyId());
        assertEquals(CONTEXT, rotationEvent.getContext());
    }

    /**
     * Verifies that rotateKEK succeeds even when there is no prior KEK
     * (first-time rotation / initial setup scenario).
     */
    @Test
    void rotateKEK_withNoPriorKEK_succeeds() {
        UUID newKEKId = UUID.randomUUID();
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(newKEKId));

        Result<UUID, KeyError> result = keyManager.rotateKEK(CONTEXT);

        assertTrue(result.isSuccess());
        assertEquals(newKEKId, result.getValue().orElseThrow());
        // No DEKs to re-encrypt, so encryptDEK / decryptDEK should not be called
        verify(kmsClient, never()).decryptDEK(any(), any());
        verify(kmsClient, never()).encryptDEK(any(), any());
    }

    /**
     * Verifies that rotateKEK returns a failure when KMS cannot generate a new KEK.
     */
    @Test
    void rotateKEK_kmsGenerationFailure_returnsError() {
        UUID oldKEKId = UUID.randomUUID();
        setupContextWithOneDEK(oldKEKId, UUID.randomUUID());

        KMSError kmsError = KMSError.of("KMS_UNAVAILABLE", "KMS is down");
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.failure(kmsError));

        Result<UUID, KeyError> result = keyManager.rotateKEK(CONTEXT);

        assertTrue(result.isFailure());
        assertEquals("KMS_KEK_GENERATION_FAILED", result.getError().orElseThrow().getCode());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: KEK rotation with multiple DEKs
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that when multiple DEKs exist for a context, all of them are
     * re-encrypted with the new KEK during rotation.
     */
    @Test
    void rotateKEK_withMultipleDEKs_reEncryptsAllDEKs() {
        UUID oldKEKId = UUID.randomUUID();
        UUID newKEKId = UUID.randomUUID();

        // Initialise KEK
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(oldKEKId));
        keyManager.initializeKEK(CONTEXT);

        // Create 3 DEKs for the same context
        int dekCount = 3;
        when(ivCounter.resetState(any())).thenReturn(Result.success(Unit.unit()));

        for (int i = 0; i < dekCount; i++) {
            EncryptedDEK encDEK = fakeEncryptedDEK(oldKEKId);
            when(kmsClient.encryptDEK(any(DEK.class), eq(oldKEKId)))
                    .thenReturn(Result.success(encDEK));
            Result<UUID, KeyError> r = keyManager.rotateDEK(CONTEXT);
            assertTrue(r.isSuccess(), "DEK rotation " + i + " should succeed");
        }

        // Prepare KEK rotation stubs
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(newKEKId));

        DEK plainDEK = DEK.of(randomDEKBytes());
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(oldKEKId)))
                .thenReturn(Result.success(plainDEK));
        EncryptedDEK reEncDEK = fakeEncryptedDEK(newKEKId);
        when(kmsClient.encryptDEK(any(DEK.class), eq(newKEKId)))
                .thenReturn(Result.success(reEncDEK));

        // Act
        Result<UUID, KeyError> result = keyManager.rotateKEK(CONTEXT);

        // Assert
        assertTrue(result.isSuccess(), "KEK rotation should succeed");

        // Each DEK should have been decrypted with old KEK and re-encrypted with new KEK
        verify(kmsClient, times(dekCount)).decryptDEK(any(EncryptedDEK.class), eq(oldKEKId));
        verify(kmsClient, times(dekCount)).encryptDEK(any(DEK.class), eq(newKEKId));
    }

    /**
     * Verifies that if re-encryption of any DEK fails, rotateKEK returns an error
     * and does not silently skip the failing DEK.
     */
    @Test
    void rotateKEK_reEncryptionFailure_returnsError() {
        UUID oldKEKId = UUID.randomUUID();
        UUID newKEKId = UUID.randomUUID();

        setupContextWithOneDEK(oldKEKId, UUID.randomUUID());

        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(newKEKId));

        DEK plainDEK = DEK.of(randomDEKBytes());
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(oldKEKId)))
                .thenReturn(Result.success(plainDEK));
        when(kmsClient.encryptDEK(any(DEK.class), eq(newKEKId)))
                .thenReturn(Result.failure(KMSError.of("KMS_ENCRYPTION_FAILED", "KMS error")));

        Result<UUID, KeyError> result = keyManager.rotateKEK(CONTEXT);

        assertTrue(result.isFailure());
        assertEquals("KMS_ENCRYPTION_FAILED", result.getError().orElseThrow().getCode());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Cache invalidation after KEK rotation
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that all DEKs for the rotated context are evicted from the cache
     * after KEK rotation, so subsequent lookups fetch fresh copies from KMS.
     */
    @Test
    void rotateKEK_invalidatesAllCachedDEKsForContext() {
        UUID oldKEKId = UUID.randomUUID();
        UUID newKEKId = UUID.randomUUID();

        // Set up context with one DEK
        UUID dekId = setupContextWithOneDEK(oldKEKId, UUID.randomUUID());

        // Populate the cache by calling getDEK (simulates a prior cache-miss fetch)
        DEK plainDEK = DEK.of(randomDEKBytes());
        EncryptedDEK encDEK = fakeEncryptedDEK(oldKEKId);
        // The DEK metadata was stored during rotateDEK; we need to stub decryptDEK for getDEK
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(oldKEKId)))
                .thenReturn(Result.success(plainDEK));
        Result<DEKWithMetadata, KeyError> getDEKResult = keyManager.getDEK(dekId);
        assertTrue(getDEKResult.isSuccess(), "getDEK should succeed before rotation");
        assertEquals(1, dekCache.size(), "Cache should contain the DEK before rotation");

        // Prepare KEK rotation stubs
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(newKEKId));
        EncryptedDEK reEncDEK = fakeEncryptedDEK(newKEKId);
        when(kmsClient.encryptDEK(any(DEK.class), eq(newKEKId)))
                .thenReturn(Result.success(reEncDEK));

        // Act
        Result<UUID, KeyError> rotateResult = keyManager.rotateKEK(CONTEXT);
        assertTrue(rotateResult.isSuccess(), "KEK rotation should succeed");

        // Assert: cache is empty after rotation
        assertEquals(0, dekCache.size(), "All DEKs for the context should be evicted from cache after KEK rotation");
    }

    /**
     * Verifies that DEKs belonging to a different context are NOT evicted when
     * a KEK rotation is performed for a specific context.
     */
    @Test
    void rotateKEK_doesNotInvalidateCacheForOtherContexts() {
        UUID profileKEKId = UUID.randomUUID();
        UUID consentKEKId = UUID.randomUUID();
        UUID newProfileKEKId = UUID.randomUUID();

        // Set up PROFILE context with one DEK
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(profileKEKId));
        keyManager.initializeKEK(CONTEXT);
        when(ivCounter.resetState(any())).thenReturn(Result.success(Unit.unit()));
        EncryptedDEK profileEncDEK = fakeEncryptedDEK(profileKEKId);
        when(kmsClient.encryptDEK(any(DEK.class), eq(profileKEKId)))
                .thenReturn(Result.success(profileEncDEK));
        Result<UUID, KeyError> profileDEKResult = keyManager.rotateDEK(CONTEXT);
        assertTrue(profileDEKResult.isSuccess());
        UUID profileDEKId = profileDEKResult.getValue().orElseThrow();

        // Set up CONSENT context with one DEK
        BoundedContext consentCtx = BoundedContext.CONSENT;
        when(kmsClient.generateKEK(consentCtx, ENV)).thenReturn(Result.success(consentKEKId));
        keyManager.initializeKEK(consentCtx);
        EncryptedDEK consentEncDEK = fakeEncryptedDEK(consentKEKId);
        when(kmsClient.encryptDEK(any(DEK.class), eq(consentKEKId)))
                .thenReturn(Result.success(consentEncDEK));
        Result<UUID, KeyError> consentDEKResult = keyManager.rotateDEK(consentCtx);
        assertTrue(consentDEKResult.isSuccess());
        UUID consentDEKId = consentDEKResult.getValue().orElseThrow();

        // Populate cache for both DEKs
        DEK profilePlainDEK = DEK.of(randomDEKBytes());
        DEK consentPlainDEK = DEK.of(randomDEKBytes());
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(profileKEKId)))
                .thenReturn(Result.success(profilePlainDEK));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(consentKEKId)))
                .thenReturn(Result.success(consentPlainDEK));
        keyManager.getDEK(profileDEKId);
        keyManager.getDEK(consentDEKId);
        assertEquals(2, dekCache.size(), "Both DEKs should be cached");

        // Rotate only PROFILE KEK
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(newProfileKEKId));
        EncryptedDEK reEncProfileDEK = fakeEncryptedDEK(newProfileKEKId);
        when(kmsClient.encryptDEK(any(DEK.class), eq(newProfileKEKId)))
                .thenReturn(Result.success(reEncProfileDEK));

        Result<UUID, KeyError> rotateResult = keyManager.rotateKEK(CONTEXT);
        assertTrue(rotateResult.isSuccess());

        // Assert: only the PROFILE DEK was evicted; CONSENT DEK remains cached
        assertEquals(1, dekCache.size(), "Only the PROFILE DEK should be evicted");
        assertTrue(dekCache.get(consentDEKId).isPresent(), "CONSENT DEK should still be in cache");
        assertFalse(dekCache.get(profileDEKId).isPresent(), "PROFILE DEK should have been evicted");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Decryption after KEK rotation
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that data encrypted before KEK rotation can still be decrypted
     * after rotation, because the DEK is re-encrypted with the new KEK and
     * remains accessible via getDEK.
     */
    @Test
    void rotateKEK_dataEncryptedBeforeRotation_isStillDecryptableAfterRotation() {
        UUID oldKEKId = UUID.randomUUID();
        UUID newKEKId = UUID.randomUUID();

        // Set up context with one DEK
        UUID dekId = setupContextWithOneDEK(oldKEKId, UUID.randomUUID());

        // Stub: decrypt DEK with old KEK (used during KEK rotation)
        DEK plainDEK = DEK.of(randomDEKBytes());
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(oldKEKId)))
                .thenReturn(Result.success(plainDEK));

        // Stub: re-encrypt DEK with new KEK
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(newKEKId));
        EncryptedDEK reEncDEK = fakeEncryptedDEK(newKEKId);
        when(kmsClient.encryptDEK(any(DEK.class), eq(newKEKId)))
                .thenReturn(Result.success(reEncDEK));

        // Perform KEK rotation
        Result<UUID, KeyError> rotateResult = keyManager.rotateKEK(CONTEXT);
        assertTrue(rotateResult.isSuccess(), "KEK rotation should succeed");

        // After rotation the cache is empty; stub decryptDEK with new KEK for getDEK
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(newKEKId)))
                .thenReturn(Result.success(plainDEK));

        // Act: retrieve the DEK that was used before rotation
        Result<DEKWithMetadata, KeyError> getDEKResult = keyManager.getDEK(dekId);

        // Assert: DEK is still retrievable after KEK rotation
        assertTrue(getDEKResult.isSuccess(),
                "DEK should be retrievable after KEK rotation (decryption of historical data must work)");

        DEKWithMetadata retrieved = getDEKResult.getValue().orElseThrow();
        assertEquals(dekId, retrieved.getKeyId());
        // The DEK's KEK reference should now point to the new KEK
        assertEquals(newKEKId, retrieved.getKekId());
    }

    /**
     * Verifies that after KEK rotation the DEK metadata is updated to reference
     * the new KEK ID, so future KMS decrypt calls use the correct KEK.
     */
    @Test
    void rotateKEK_updatesDEKMetadataWithNewKEKId() {
        UUID oldKEKId = UUID.randomUUID();
        UUID newKEKId = UUID.randomUUID();

        UUID dekId = setupContextWithOneDEK(oldKEKId, UUID.randomUUID());

        DEK plainDEK = DEK.of(randomDEKBytes());
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(oldKEKId)))
                .thenReturn(Result.success(plainDEK));
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(newKEKId));
        EncryptedDEK reEncDEK = fakeEncryptedDEK(newKEKId);
        when(kmsClient.encryptDEK(any(DEK.class), eq(newKEKId)))
                .thenReturn(Result.success(reEncDEK));

        keyManager.rotateKEK(CONTEXT);

        // Stub getDEK to use new KEK
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(newKEKId)))
                .thenReturn(Result.success(plainDEK));

        Result<DEKWithMetadata, KeyError> result = keyManager.getDEK(dekId);
        assertTrue(result.isSuccess());
        assertEquals(newKEKId, result.getValue().orElseThrow().getKekId(),
                "DEK metadata should reference the new KEK after rotation");
    }

    /**
     * Verifies that after KEK rotation, the new KEK ID is returned by subsequent
     * getActiveDEK calls (via the active DEK's updated kekId).
     */
    @Test
    void rotateKEK_subsequentGetActiveDEKUsesNewKEK() {
        UUID oldKEKId = UUID.randomUUID();
        UUID newKEKId = UUID.randomUUID();

        setupContextWithOneDEK(oldKEKId, UUID.randomUUID());

        DEK plainDEK = DEK.of(randomDEKBytes());
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(oldKEKId)))
                .thenReturn(Result.success(plainDEK));
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(newKEKId));
        EncryptedDEK reEncDEK = fakeEncryptedDEK(newKEKId);
        when(kmsClient.encryptDEK(any(DEK.class), eq(newKEKId)))
                .thenReturn(Result.success(reEncDEK));

        keyManager.rotateKEK(CONTEXT);

        // Stub getActiveDEK path: cache miss → decryptDEK with new KEK
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(newKEKId)))
                .thenReturn(Result.success(plainDEK));

        Result<DEKWithMetadata, KeyError> activeResult = keyManager.getActiveDEK(CONTEXT);
        assertTrue(activeResult.isSuccess());
        assertEquals(newKEKId, activeResult.getValue().orElseThrow().getKekId(),
                "Active DEK should reference the new KEK after rotation");
    }
}
