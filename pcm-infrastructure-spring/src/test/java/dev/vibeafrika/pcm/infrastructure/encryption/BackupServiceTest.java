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
import static org.mockito.Mockito.lenient;

/**
 * Unit tests for {@link BackupService}.
 *
 * <p>Tests verify:
 * <ul>
 *   <li>Backup records contain only ciphertext (no plaintext PII)</li>
 *   <li>Key version history is tracked correctly</li>
 *   <li>KEK export with offline master key</li>
 *   <li>Audit log backup</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class BackupServiceTest {

    @Mock
    private IKeyManager keyManager;

    @Mock
    private IAuditLogger auditLogger;

    @Mock
    private IKMSClient kmsClient;

    private BackupService backupService;

    private static final BoundedContext CONTEXT = BoundedContext.PROFILE;
    private static final Environment ENV = Environment.PROD;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeEach
    void setUp() {
        byte[] signingKey = new byte[32];
        RANDOM.nextBytes(signingKey);
        backupService = new BackupService(keyManager, auditLogger, kmsClient, ENV, signingKey);

        lenient().when(auditLogger.logSecurityEvent(any())).thenReturn(
                Result.failure(AuditError.of("NOOP", "no-op")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Backup records contain only ciphertext
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that a BackupRecord holds only ciphertext — never plaintext PII.
     * The BackupRecord type enforces this by accepting only a Ciphertext value object.
     */
    @Test
    void backupRecord_containsOnlyCiphertext_neverPlaintext() {
        UUID dekId = UUID.randomUUID();
        Ciphertext ciphertext = createFakeCiphertext(dekId);

        BackupRecord record = BackupRecord.of(
                UUID.randomUUID(),
                ciphertext,
                dekId,
                CONTEXT,
                "email",
                Instant.now()
        );

        // The record stores ciphertext, not plaintext
        assertNotNull(record.getCiphertext(), "Backup record must contain ciphertext");
        assertEquals(ciphertext, record.getCiphertext(), "Ciphertext must match what was stored");

        // The field identifier is the field name, not the value
        assertEquals("email", record.getFieldIdentifier(),
                "Field identifier must be the field name, not the plaintext value");
    }

    /**
     * Verifies that createBackup produces a certificate with the correct context
     * and that backup records are stored.
     */
    @Test
    void createBackup_withRegisteredRecords_returnsCertificateWithCorrectContext() {
        UUID dekId = UUID.randomUUID();
        Ciphertext ciphertext = createFakeCiphertext(dekId);

        // Register a backup record (ciphertext only)
        BackupRecord record = BackupRecord.of(
                UUID.randomUUID(), ciphertext, dekId, CONTEXT, "email", Instant.now());
        backupService.registerBackupRecord(record);

        // Register key version history so the backup knows which DEKs were active
        KeyVersionHistory kvh = KeyVersionHistory.builder()
                .dekId(dekId)
                .kekId(UUID.randomUUID())
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(Instant.now().minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ACTIVE)
                .build();
        backupService.recordKeyVersionHistory(kvh);

        Instant backupTime = Instant.now();
        Result<BackupCertificate, BackupError> result = backupService.createBackup(CONTEXT, backupTime);

        assertTrue(result.isSuccess(), "Backup creation should succeed");
        BackupCertificate certificate = result.getValue().orElseThrow();

        assertEquals(CONTEXT, certificate.getContext(), "Certificate context must match");
        assertEquals(backupTime, certificate.getBackupTimestamp(), "Certificate timestamp must match");
        assertNotNull(certificate.getBackupId(), "Certificate must have a backup ID");
        assertNotNull(certificate.getSignature(), "Certificate must have a signature");
    }

    /**
     * Verifies that backup records registered via registerBackupRecord are
     * included in the backup and the certificate records the count.
     */
    @Test
    void createBackup_recordsCountMatchesRegisteredRecords() {
        UUID dekId = UUID.randomUUID();

        // Register key version history
        KeyVersionHistory kvh = KeyVersionHistory.builder()
                .dekId(dekId)
                .kekId(UUID.randomUUID())
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(Instant.now().minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ACTIVE)
                .build();
        backupService.recordKeyVersionHistory(kvh);

        // Register 3 backup records
        for (int i = 0; i < 3; i++) {
            BackupRecord record = BackupRecord.of(
                    UUID.randomUUID(),
                    createFakeCiphertext(dekId),
                    dekId,
                    CONTEXT,
                    "field_" + i,
                    Instant.now()
            );
            backupService.registerBackupRecord(record);
        }

        Result<BackupCertificate, BackupError> result =
                backupService.createBackup(CONTEXT, Instant.now());

        assertTrue(result.isSuccess());
        assertEquals(3, result.getValue().orElseThrow().getRecordCount(),
                "Certificate must record the correct number of backup records");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Key version history tracking 
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that key version history is recorded and retrievable.
     */
    @Test
    void getKeyVersionHistory_afterRecordingHistory_returnsAllEntries() {
        UUID dek1 = UUID.randomUUID();
        UUID dek2 = UUID.randomUUID();
        UUID kekId = UUID.randomUUID();

        Instant now = Instant.now();

        KeyVersionHistory kvh1 = KeyVersionHistory.builder()
                .dekId(dek1)
                .kekId(kekId)
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(now.minus(90, ChronoUnit.DAYS))
                .rotatedAt(now.minus(1, ChronoUnit.DAYS))
                .status(KeyStatus.ROTATED)
                .build();

        KeyVersionHistory kvh2 = KeyVersionHistory.builder()
                .dekId(dek2)
                .kekId(kekId)
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(now.minus(1, ChronoUnit.DAYS))
                .status(KeyStatus.ACTIVE)
                .build();

        backupService.recordKeyVersionHistory(kvh1);
        backupService.recordKeyVersionHistory(kvh2);

        Result<List<KeyVersionHistory>, BackupError> result =
                backupService.getKeyVersionHistory(CONTEXT);

        assertTrue(result.isSuccess(), "Key version history retrieval should succeed");
        List<KeyVersionHistory> history = result.getValue().orElseThrow();
        assertEquals(2, history.size(), "Should have 2 key version history entries");
        assertTrue(history.stream().anyMatch(h -> h.getDekId().equals(dek1)),
                "History should contain DEK 1");
        assertTrue(history.stream().anyMatch(h -> h.getDekId().equals(dek2)),
                "History should contain DEK 2");
    }

    /**
     * Verifies that wasActiveAt correctly identifies which DEK was active at a given time.
     */
    @Test
    void keyVersionHistory_wasActiveAt_correctlyIdentifiesActiveKey() {
        Instant now = Instant.now();
        Instant rotationTime = now.minus(1, ChronoUnit.DAYS);

        KeyVersionHistory oldKey = KeyVersionHistory.builder()
                .dekId(UUID.randomUUID())
                .kekId(UUID.randomUUID())
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(now.minus(90, ChronoUnit.DAYS))
                .rotatedAt(rotationTime)
                .status(KeyStatus.ROTATED)
                .build();

        KeyVersionHistory newKey = KeyVersionHistory.builder()
                .dekId(UUID.randomUUID())
                .kekId(UUID.randomUUID())
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(rotationTime)
                .status(KeyStatus.ACTIVE)
                .build();

        // Old key was active before rotation
        assertTrue(oldKey.wasActiveAt(now.minus(2, ChronoUnit.DAYS)),
                "Old key should be active before rotation");
        assertFalse(oldKey.wasActiveAt(now),
                "Old key should not be active after rotation");

        // New key is active after rotation
        assertTrue(newKey.wasActiveAt(now),
                "New key should be active after creation");
        assertFalse(newKey.wasActiveAt(now.minus(2, ChronoUnit.DAYS)),
                "New key should not be active before creation");
    }

    /**
     * Verifies that the backup certificate includes the DEK IDs that were active
     * at backup time, enabling historical decryption.
     */
    @Test
    void createBackup_certificateIncludesActiveDekIds() {
        UUID activeDekId = UUID.randomUUID();
        UUID rotatedDekId = UUID.randomUUID();
        UUID kekId = UUID.randomUUID();
        Instant now = Instant.now();

        // Active DEK
        KeyVersionHistory activeKvh = KeyVersionHistory.builder()
                .dekId(activeDekId)
                .kekId(kekId)
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(now.minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ACTIVE)
                .build();

        // Rotated DEK (was active 2 days ago, rotated 1 day ago)
        KeyVersionHistory rotatedKvh = KeyVersionHistory.builder()
                .dekId(rotatedDekId)
                .kekId(kekId)
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(now.minus(2, ChronoUnit.DAYS))
                .rotatedAt(now.minus(1, ChronoUnit.DAYS))
                .status(KeyStatus.ROTATED)
                .build();

        backupService.recordKeyVersionHistory(activeKvh);
        backupService.recordKeyVersionHistory(rotatedKvh);

        // Backup taken now — only the active DEK should be in the certificate
        Result<BackupCertificate, BackupError> result = backupService.createBackup(CONTEXT, now);

        assertTrue(result.isSuccess());
        BackupCertificate certificate = result.getValue().orElseThrow();

        assertTrue(certificate.getDekIdsAtBackupTime().contains(activeDekId),
                "Certificate must include the active DEK ID");
        assertFalse(certificate.getDekIdsAtBackupTime().contains(rotatedDekId),
                "Certificate must not include the rotated DEK ID (not active at backup time)");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: KEK export with offline master key 
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that KEK export produces a bundle with the correct offline master key ID.
     */
    @Test
    void exportKEKsWithOfflineMasterKey_returnsBundle() {
        String offlineMasterKeyId = "offline-master-key-001";

        // Register some key version history so there are KEKs to export
        UUID kekId = UUID.randomUUID();
        KeyVersionHistory kvh = KeyVersionHistory.builder()
                .dekId(UUID.randomUUID())
                .kekId(kekId)
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(Instant.now().minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ACTIVE)
                .build();
        backupService.recordKeyVersionHistory(kvh);

        Result<KeyExportBundle, BackupError> result =
                backupService.exportKEKsWithOfflineMasterKey(offlineMasterKeyId);

        assertTrue(result.isSuccess(), "KEK export should succeed");
        KeyExportBundle bundle = result.getValue().orElseThrow();

        assertEquals(offlineMasterKeyId, bundle.getOfflineMasterKeyId(),
                "Bundle must reference the correct offline master key");
        assertEquals(ENV, bundle.getEnvironment(), "Bundle must be for the correct environment");
        assertNotNull(bundle.getBundleId(), "Bundle must have an ID");
        assertNotNull(bundle.getExportedAt(), "Bundle must have an export timestamp");
    }

    /**
     * Verifies that exported KEKs have encrypted material (not raw key bytes).
     */
    @Test
    void exportKEKsWithOfflineMasterKey_exportedKEKsHaveEncryptedMaterial() {
        String offlineMasterKeyId = "offline-master-key-001";

        UUID kekId = UUID.randomUUID();
        KeyVersionHistory kvh = KeyVersionHistory.builder()
                .dekId(UUID.randomUUID())
                .kekId(kekId)
                .context(CONTEXT)
                .environment(ENV)
                .createdAt(Instant.now().minus(1, ChronoUnit.HOURS))
                .status(KeyStatus.ACTIVE)
                .build();
        backupService.recordKeyVersionHistory(kvh);

        Result<KeyExportBundle, BackupError> result =
                backupService.exportKEKsWithOfflineMasterKey(offlineMasterKeyId);

        assertTrue(result.isSuccess());
        KeyExportBundle bundle = result.getValue().orElseThrow();

        assertFalse(bundle.getExportedKEKs().isEmpty(),
                "Bundle must contain at least one exported KEK");

        for (KeyExportBundle.ExportedKEK exportedKEK : bundle.getExportedKEKs()) {
            assertNotNull(exportedKEK.getEncryptedKEKMaterial(),
                    "Exported KEK must have encrypted material");
            assertTrue(exportedKEK.getEncryptedKEKMaterial().length > 0,
                    "Encrypted KEK material must not be empty");
            assertNotNull(exportedKEK.getKekId(), "Exported KEK must have an ID");
            assertNotNull(exportedKEK.getContext(), "Exported KEK must have a context");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Audit log backup 
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that audit log backup succeeds for a valid time range.
     */
    @Test
    void backupAuditLogs_validTimeRange_succeeds() {
        Instant from = Instant.now().minus(1, ChronoUnit.HOURS);
        Instant to = Instant.now();

        Result<Void, BackupError> result = backupService.backupAuditLogs(from, to);

        assertTrue(result.isSuccess(), "Audit log backup should succeed for valid time range");
    }

    /**
     * Verifies that audit log backup records the backup entry.
     */
    @Test
    void backupAuditLogs_recordsBackupEntry() {
        Instant from = Instant.now().minus(2, ChronoUnit.HOURS);
        Instant to = Instant.now().minus(1, ChronoUnit.HOURS);

        backupService.backupAuditLogs(from, to);

        List<BackupService.AuditLogBackupEntry> entries = backupService.getAuditLogBackupEntries();
        assertFalse(entries.isEmpty(), "Audit log backup entries should be recorded");

        BackupService.AuditLogBackupEntry entry = entries.get(entries.size() - 1);
        assertEquals(from, entry.getFrom(), "Backup entry must record the from timestamp");
        assertEquals(to, entry.getTo(), "Backup entry must record the to timestamp");
        assertNotNull(entry.getBackedUpAt(), "Backup entry must record when it was backed up");
    }

    /**
     * Verifies that audit log backup fails when the time range is invalid (to before from).
     */
    @Test
    void backupAuditLogs_invalidTimeRange_returnsError() {
        Instant from = Instant.now();
        Instant to = Instant.now().minus(1, ChronoUnit.HOURS); // to is before from

        Result<Void, BackupError> result = backupService.backupAuditLogs(from, to);

        assertTrue(result.isFailure(), "Audit log backup should fail for invalid time range");
        assertEquals("INVALID_TIME_RANGE", result.getError().orElseThrow().getCode(),
                "Error code must be INVALID_TIME_RANGE");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test: Empty context returns empty history
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that getKeyVersionHistory returns an empty list for a context with no history.
     */
    @Test
    void getKeyVersionHistory_noHistory_returnsEmptyList() {
        Result<List<KeyVersionHistory>, BackupError> result =
                backupService.getKeyVersionHistory(BoundedContext.CONSENT);

        assertTrue(result.isSuccess(), "Key version history retrieval should succeed even with no history");
        assertTrue(result.getValue().orElseThrow().isEmpty(),
                "Key version history should be empty for context with no history");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Creates a fake ciphertext with the minimum valid format.
     * Format: [version(1)][alg(1)][keyId(16)][IV(12)][ciphertext(0)][tag(16)] = 46 bytes
     */
    private Ciphertext createFakeCiphertext(UUID dekId) {
        byte[] bytes = new byte[46];
        bytes[0] = 0x01; // version
        bytes[1] = 0x01; // AES-256-GCM
        // Write DEK UUID as big-endian bytes at offset 2
        long msb = dekId.getMostSignificantBits();
        long lsb = dekId.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) {
            bytes[2 + i] = (byte) (msb >>> (56 - 8 * i));
            bytes[10 + i] = (byte) (lsb >>> (56 - 8 * i));
        }
        // IV at bytes 18-29 (12 bytes) — leave as zeros
        // Auth tag at bytes 30-45 (16 bytes) — leave as zeros
        return Ciphertext.of(bytes);
    }
}
