package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link RestoreService}.
 *
 * <p>Tests verify:
 * <ul>
 *   <li>Restore point identification from key version history</li>
 *   <li>Key availability verification before restore</li>
 *   <li>Restore with historical keys</li>
 *   <li>Restored data can be decrypted</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class RestoreServiceTest {

    @Mock
    private IKeyManager keyManager;

    @Mock
    private IEncryptionService encryptionService;

    @Mock
    private IAuditLogger auditLogger;

    @Mock
    private IKMSClient kmsClient;

    private BackupService backupService;
    private RestoreService restoreService;

    private static final BoundedContext CONTEXT = BoundedContext.PROFILE;
    private static final Environment ENV = Environment.PROD;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeEach
    void setUp() {
        byte[] signingKey = new byte[32];
        RANDOM.nextBytes(signingKey);
        backupService = new BackupService(keyManager, auditLogger, kmsClient, ENV, signingKey);
        restoreService = new RestoreService(keyManager, encryptionService, backupService);

        lenient().when(auditLogger.logSecurityEvent(any())).thenReturn(
                Result.failure(AuditError.of("NOOP", "no-op")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Restore point identification 
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that identifyRestorePoint returns a restore point with the correct
     * target timestamp and required DEK IDs.
     */
    @Test
    void identifyRestorePoint_withKeyHistory_returnsRestorePoint() {
        UUID dekId = UUID.randomUUID();
        Instant now = Instant.now();

        // Register key version history
        KeyVersionHistory kvh = KeyVersionHistory.builder()
                .dekId(dekId)
                .kekId(UUID.randomUUID())
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(now.minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ACTIVE)
                .build();
        backupService.recordKeyVersionHistory(kvh);

        Result<RestorePoint, RestoreError> result = restoreService.identifyRestorePoint(now);

        assertTrue(result.isSuccess(), "Restore point identification should succeed");
        RestorePoint restorePoint = result.getValue().orElseThrow();

        assertEquals(now, restorePoint.getTargetTimestamp(),
                "Restore point must have the correct target timestamp");
        assertTrue(restorePoint.getRequiredDekIds().contains(dekId),
                "Restore point must include the active DEK ID");
        assertNotNull(restorePoint.getRestorePointId(), "Restore point must have an ID");
        assertNotNull(restorePoint.getBackupId(), "Restore point must reference a backup");
    }

    /**
     * Verifies that identifyRestorePoint fails when no key history exists for the timestamp.
     */
    @Test
    void identifyRestorePoint_noKeyHistory_returnsError() {
        // No key version history registered
        Instant targetTimestamp = Instant.now();

        Result<RestorePoint, RestoreError> result =
                restoreService.identifyRestorePoint(targetTimestamp);

        assertTrue(result.isFailure(), "Restore point identification should fail with no key history");
        assertEquals("NO_RESTORE_POINT", result.getError().orElseThrow().getCode(),
                "Error code must be NO_RESTORE_POINT");
    }

    /**
     * Verifies that identifyRestorePoint only includes DEKs that were active at the target timestamp.
     */
    @Test
    void identifyRestorePoint_onlyIncludesActiveDeKsAtTargetTime() {
        Instant now = Instant.now();
        UUID activeDekId = UUID.randomUUID();
        UUID futureDekId = UUID.randomUUID();

        // Active DEK (created 1 hour ago)
        KeyVersionHistory activeKvh = KeyVersionHistory.builder()
                .dekId(activeDekId)
                .kekId(UUID.randomUUID())
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(now.minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ACTIVE)
                .build();

        // Future DEK (created 1 hour in the future — should not be included)
        KeyVersionHistory futureKvh = KeyVersionHistory.builder()
                .dekId(futureDekId)
                .kekId(UUID.randomUUID())
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(now.plus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ACTIVE)
                .build();

        backupService.recordKeyVersionHistory(activeKvh);
        backupService.recordKeyVersionHistory(futureKvh);

        // Restore to "now" — only the active DEK should be included
        Result<RestorePoint, RestoreError> result = restoreService.identifyRestorePoint(now);

        assertTrue(result.isSuccess());
        RestorePoint restorePoint = result.getValue().orElseThrow();

        assertTrue(restorePoint.getRequiredDekIds().contains(activeDekId),
                "Restore point must include the DEK active at target time");
        assertFalse(restorePoint.getRequiredDekIds().contains(futureDekId),
                "Restore point must not include DEKs created after target time");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Key availability verification 
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that verifyKeyAvailability returns true when all required DEKs are available.
     */
    @Test
    void verifyKeyAvailability_allKeysAvailable_returnsTrue() {
        UUID dekId = UUID.randomUUID();
        UUID kekId = UUID.randomUUID();

        RestorePoint restorePoint = RestorePoint.of(
                UUID.randomUUID(),
                Instant.now(),
                CONTEXT,
                List.of(dekId),
                UUID.randomUUID()
        );

        // Mock DEK retrieval to succeed
        DEKWithMetadata dekMetadata = DEKWithMetadata.builder()
                .dek(DEK.of(randomBytes(32)))
                .keyId(dekId)
                .kekId(kekId)
                .context(CONTEXT)
                .environment(ENV)
                .algorithm(EncryptionAlgorithm.AES_256_GCM)
                .createdAt(Instant.now().minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ROTATED)
                .build();

        when(keyManager.getDEK(dekId)).thenReturn(Result.success(dekMetadata));

        Result<Boolean, RestoreError> result = restoreService.verifyKeyAvailability(restorePoint);

        assertTrue(result.isSuccess(), "Key availability check should succeed");
        assertTrue(result.getValue().orElseThrow(), "All keys should be available");
    }

    /**
     * Verifies that verifyKeyAvailability returns an error when a required DEK is missing.
     */
    @Test
    void verifyKeyAvailability_missingKey_returnsError() {
        UUID missingDekId = UUID.randomUUID();

        RestorePoint restorePoint = RestorePoint.of(
                UUID.randomUUID(),
                Instant.now(),
                CONTEXT,
                List.of(missingDekId),
                UUID.randomUUID()
        );

        // Mock DEK retrieval to fail (key not found)
        when(keyManager.getDEK(missingDekId)).thenReturn(
                Result.failure(KeyError.of("KEY_NOT_FOUND", "DEK not found: " + missingDekId)));

        Result<Boolean, RestoreError> result = restoreService.verifyKeyAvailability(restorePoint);

        assertTrue(result.isFailure(), "Key availability check should fail when DEK is missing");
        assertEquals("KEYS_UNAVAILABLE", result.getError().orElseThrow().getCode(),
                "Error code must be KEYS_UNAVAILABLE");
    }

    /**
     * Verifies that verifyKeyAvailability checks all required DEKs, not just the first.
     */
    @Test
    void verifyKeyAvailability_multipleKeys_checksAll() {
        UUID availableDekId = UUID.randomUUID();
        UUID missingDekId = UUID.randomUUID();
        UUID kekId = UUID.randomUUID();

        RestorePoint restorePoint = RestorePoint.of(
                UUID.randomUUID(),
                Instant.now(),
                CONTEXT,
                List.of(availableDekId, missingDekId),
                UUID.randomUUID()
        );

        DEKWithMetadata availableDek = DEKWithMetadata.builder()
                .dek(DEK.of(randomBytes(32)))
                .keyId(availableDekId)
                .kekId(kekId)
                .context(CONTEXT)
                .environment(ENV)
                .algorithm(EncryptionAlgorithm.AES_256_GCM)
                .createdAt(Instant.now().minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ROTATED)
                .build();

        when(keyManager.getDEK(availableDekId)).thenReturn(Result.success(availableDek));
        when(keyManager.getDEK(missingDekId)).thenReturn(
                Result.failure(KeyError.of("KEY_NOT_FOUND", "DEK not found")));

        Result<Boolean, RestoreError> result = restoreService.verifyKeyAvailability(restorePoint);

        assertTrue(result.isFailure(), "Key availability check should fail when any DEK is missing");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Restore with historical keys
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that restoreCiphertext succeeds when all keys are available.
     */
    @Test
    void restoreCiphertext_allKeysAvailable_succeeds() {
        UUID dekId = UUID.randomUUID();
        UUID kekId = UUID.randomUUID();
        UUID backupId = UUID.randomUUID();

        // Register a backup record
        Ciphertext ciphertext = createFakeCiphertext(dekId);
        BackupRecord record = BackupRecord.of(
                UUID.randomUUID(), ciphertext, dekId, CONTEXT, "email", Instant.now());
        backupService.registerBackupRecord(record);

        // Register key version history
        KeyVersionHistory kvh = KeyVersionHistory.builder()
                .dekId(dekId)
                .kekId(kekId)
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(Instant.now().minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ACTIVE)
                .build();
        backupService.recordKeyVersionHistory(kvh);

        // Create backup to get a real backup ID
        Result<BackupCertificate, BackupError> backupResult =
                backupService.createBackup(CONTEXT, Instant.now());
        assertTrue(backupResult.isSuccess());
        BackupCertificate certificate = backupResult.getValue().orElseThrow();

        RestorePoint restorePoint = RestorePoint.of(
                UUID.randomUUID(),
                Instant.now(),
                CONTEXT,
                List.of(dekId),
                certificate.getBackupId()
        );

        // Mock key availability
        DEKWithMetadata dekMetadata = DEKWithMetadata.builder()
                .dek(DEK.of(randomBytes(32)))
                .keyId(dekId)
                .kekId(kekId)
                .context(CONTEXT)
                .environment(ENV)
                .algorithm(EncryptionAlgorithm.AES_256_GCM)
                .createdAt(Instant.now().minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ACTIVE)
                .build();
        when(keyManager.getDEK(dekId)).thenReturn(Result.success(dekMetadata));

        Result<RestoreResult, RestoreError> result =
                restoreService.restoreCiphertext(restorePoint, certificate);

        assertTrue(result.isSuccess(), "Restore should succeed when all keys are available");
        RestoreResult restoreResult = result.getValue().orElseThrow();

        assertEquals(certificate.getBackupId(), restoreResult.getBackupId(),
                "Restore result must reference the correct backup");
        assertEquals(CONTEXT, restoreResult.getContext(),
                "Restore result must have the correct context");
        assertNotNull(restoreResult.getRestoreId(), "Restore result must have an ID");
        assertNotNull(restoreResult.getRestoredAt(), "Restore result must have a timestamp");
    }

    /**
     * Verifies that restoreCiphertext fails when required keys are unavailable.
     */
    @Test
    void restoreCiphertext_missingKeys_returnsError() {
        UUID missingDekId = UUID.randomUUID();
        UUID backupId = UUID.randomUUID();

        BackupCertificate certificate = BackupCertificate.of(
                backupId, CONTEXT, Instant.now(), List.of(missingDekId), 0, "sig");

        RestorePoint restorePoint = RestorePoint.of(
                UUID.randomUUID(), Instant.now(), CONTEXT, List.of(missingDekId), backupId);

        when(keyManager.getDEK(missingDekId)).thenReturn(
                Result.failure(KeyError.of("KEY_NOT_FOUND", "DEK not found")));

        Result<RestoreResult, RestoreError> result =
                restoreService.restoreCiphertext(restorePoint, certificate);

        assertTrue(result.isFailure(), "Restore should fail when required keys are unavailable");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Decryption test with historical keys 
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that testDecryptionWithHistoricalKeys succeeds when all records can be decrypted.
     */
    @Test
    void testDecryptionWithHistoricalKeys_allRecordsDecryptable_returnsTrue() {
        UUID dekId = UUID.randomUUID();
        UUID kekId = UUID.randomUUID();

        // Register a backup record
        Ciphertext ciphertext = createFakeCiphertext(dekId);
        BackupRecord record = BackupRecord.of(
                UUID.randomUUID(), ciphertext, dekId, CONTEXT, "email", Instant.now());
        backupService.registerBackupRecord(record);

        // Create backup to get a real backup ID
        KeyVersionHistory kvh = KeyVersionHistory.builder()
                .dekId(dekId).kekId(kekId).context(CONTEXT).environment(ENV)
                .createdAt(Instant.now().minus(1, ChronoUnit.HOURS)).status(KeyStatus.ACTIVE)
                .build();
        backupService.recordKeyVersionHistory(kvh);
        Result<BackupCertificate, BackupError> backupResult =
                backupService.createBackup(CONTEXT, Instant.now());
        assertTrue(backupResult.isSuccess());
        UUID backupId = backupResult.getValue().orElseThrow().getBackupId();

        RestorePoint restorePoint = RestorePoint.of(
                UUID.randomUUID(), Instant.now(), CONTEXT, List.of(dekId), backupId);

        // Mock DEK retrieval
        DEKWithMetadata dekMetadata = DEKWithMetadata.builder()
                .dek(DEK.of(randomBytes(32)))
                .keyId(dekId).kekId(kekId).context(CONTEXT).environment(ENV)
                .algorithm(EncryptionAlgorithm.AES_256_GCM)
                .createdAt(Instant.now().minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ACTIVE).build();
        when(keyManager.getDEK(dekId)).thenReturn(Result.success(dekMetadata));

        // Mock decryption to succeed
        when(encryptionService.decrypt(eq(ciphertext), eq(CONTEXT)))
                .thenReturn(Result.success("decrypted-value"));

        Result<Boolean, RestoreError> result =
                restoreService.testDecryptionWithHistoricalKeys(restorePoint);

        assertTrue(result.isSuccess(), "Decryption test should succeed");
        assertTrue(result.getValue().orElseThrow(), "Decryption test should return true");
    }

    /**
     * Verifies that testDecryptionWithHistoricalKeys fails when decryption fails.
     */
    @Test
    void testDecryptionWithHistoricalKeys_decryptionFails_returnsError() {
        UUID dekId = UUID.randomUUID();
        UUID kekId = UUID.randomUUID();

        // Register a backup record
        Ciphertext ciphertext = createFakeCiphertext(dekId);
        BackupRecord record = BackupRecord.of(
                UUID.randomUUID(), ciphertext, dekId, CONTEXT, "email", Instant.now());
        backupService.registerBackupRecord(record);

        // Create backup
        KeyVersionHistory kvh = KeyVersionHistory.builder()
                .dekId(dekId).kekId(kekId).context(CONTEXT).environment(ENV)
                .createdAt(Instant.now().minus(1, ChronoUnit.HOURS)).status(KeyStatus.ACTIVE)
                .build();
        backupService.recordKeyVersionHistory(kvh);
        Result<BackupCertificate, BackupError> backupResult =
                backupService.createBackup(CONTEXT, Instant.now());
        assertTrue(backupResult.isSuccess());
        UUID backupId = backupResult.getValue().orElseThrow().getBackupId();

        RestorePoint restorePoint = RestorePoint.of(
                UUID.randomUUID(), Instant.now(), CONTEXT, List.of(dekId), backupId);

        // Mock DEK retrieval to succeed
        DEKWithMetadata dekMetadata = DEKWithMetadata.builder()
                .dek(DEK.of(randomBytes(32)))
                .keyId(dekId).kekId(kekId).context(CONTEXT).environment(ENV)
                .algorithm(EncryptionAlgorithm.AES_256_GCM)
                .createdAt(Instant.now().minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ACTIVE).build();
        when(keyManager.getDEK(dekId)).thenReturn(Result.success(dekMetadata));

        // Mock decryption to fail (simulating corrupted ciphertext)
        when(encryptionService.decrypt(eq(ciphertext), eq(CONTEXT)))
                .thenReturn(Result.failure(DecryptionError.of(
                        "TAMPERING_DETECTED", "Authentication tag verification failed")));

        Result<Boolean, RestoreError> result =
                restoreService.testDecryptionWithHistoricalKeys(restorePoint);

        assertTrue(result.isFailure(), "Decryption test should fail when decryption fails");
        assertEquals("DECRYPTION_TEST_FAILED", result.getError().orElseThrow().getCode(),
                "Error code must be DECRYPTION_TEST_FAILED");
    }

    /**
     * Verifies that testDecryptionWithHistoricalKeys returns true for an empty backup.
     */
    @Test
    void testDecryptionWithHistoricalKeys_emptyBackup_returnsTrue() {
        UUID backupId = UUID.randomUUID();

        RestorePoint restorePoint = RestorePoint.of(
                UUID.randomUUID(), Instant.now(), CONTEXT, List.of(), backupId);

        Result<Boolean, RestoreError> result =
                restoreService.testDecryptionWithHistoricalKeys(restorePoint);

        assertTrue(result.isSuccess(), "Decryption test should succeed for empty backup");
        assertTrue(result.getValue().orElseThrow(),
                "Decryption test should return true for empty backup");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    /**
     * Creates a fake ciphertext with the minimum valid format.
     * Format: [version(1)][alg(1)][keyId(16)][IV(12)][ciphertext(0)][tag(16)] = 46 bytes
     */
    private Ciphertext createFakeCiphertext(UUID dekId) {
        byte[] bytes = new byte[46];
        bytes[0] = 0x01; // version
        bytes[1] = 0x01; // AES-256-GCM
        long msb = dekId.getMostSignificantBits();
        long lsb = dekId.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) {
            bytes[2 + i] = (byte) (msb >>> (56 - 8 * i));
            bytes[10 + i] = (byte) (lsb >>> (56 - 8 * i));
        }
        return Ciphertext.of(bytes);
    }
}
