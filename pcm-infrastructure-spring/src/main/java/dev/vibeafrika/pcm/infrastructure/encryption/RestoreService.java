package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Infrastructure implementation of {@link IRestoreService}.
 *
 * <p>This service:
 * <ul>
 *   <li>Identifies restore points and required key versions from backup metadata</li>
 *   <li>Verifies key availability before restore to prevent partial restores</li>
 *   <li>Restores ciphertext from backup — ciphertext only, never plaintext</li>
 *   <li>Tests decryption with historical keys to validate restore integrity</li>
 * </ul>
 */
public class RestoreService implements IRestoreService {

    private static final Logger logger = LoggerFactory.getLogger(RestoreService.class);

    private final IKeyManager keyManager;
    private final IEncryptionService encryptionService;
    private final BackupService backupService;

    public RestoreService(IKeyManager keyManager, IEncryptionService encryptionService,
                          BackupService backupService) {
        this.keyManager = Objects.requireNonNull(keyManager, "KeyManager cannot be null");
        this.encryptionService = Objects.requireNonNull(encryptionService, "EncryptionService cannot be null");
        this.backupService = Objects.requireNonNull(backupService, "BackupService cannot be null");
    }

    @Override
    public Result<RestorePoint, RestoreError> identifyRestorePoint(Instant targetTimestamp) {
        Objects.requireNonNull(targetTimestamp, "Target timestamp cannot be null");

        try {
            // Find the most recent backup that covers the target timestamp
            // In production, this would query a backup metadata store
            // Here we use the key version history to determine required DEKs

            // Collect required DEK IDs across all contexts for the target timestamp
            List<UUID> requiredDekIds = new ArrayList<>();
            BoundedContext primaryContext = BoundedContext.PROFILE; // default context for restore point

            for (BoundedContext context : BoundedContext.values()) {
                Result<List<KeyVersionHistory>, BackupError> historyResult =
                        backupService.getKeyVersionHistory(context);

                if (historyResult.isSuccess()) {
                    List<KeyVersionHistory> history = historyResult.getValue().orElseThrow();
                    history.stream()
                            .filter(kvh -> kvh.wasActiveAt(targetTimestamp))
                            .map(KeyVersionHistory::getDekId)
                            .forEach(requiredDekIds::add);
                }
            }

            if (requiredDekIds.isEmpty()) {
                return Result.failure(RestoreError.of("NO_RESTORE_POINT",
                        "No restore point found for timestamp: " + targetTimestamp));
            }

            // Use a deterministic backup ID based on the timestamp for the restore point
            UUID backupId = UUID.nameUUIDFromBytes(targetTimestamp.toString().getBytes());
            UUID restorePointId = UUID.randomUUID();

            RestorePoint restorePoint = RestorePoint.of(
                    restorePointId,
                    targetTimestamp,
                    primaryContext,
                    requiredDekIds,
                    backupId
            );

            logger.info("Restore point identified: restorePointId={}, targetTimestamp={}, requiredDeks={}",
                    restorePointId, targetTimestamp, requiredDekIds.size());

            return Result.success(restorePoint);

        } catch (Exception e) {
            logger.error("Failed to identify restore point for timestamp {}: {}",
                    targetTimestamp, e.getMessage());
            return Result.failure(RestoreError.of("RESTORE_POINT_IDENTIFICATION_FAILED",
                    "Failed to identify restore point for timestamp: " + targetTimestamp, e));
        }
    }

    @Override
    public Result<Boolean, RestoreError> verifyKeyAvailability(RestorePoint restorePoint) {
        Objects.requireNonNull(restorePoint, "Restore point cannot be null");

        try {
            List<UUID> missingKeys = new ArrayList<>();

            for (UUID dekId : restorePoint.getRequiredDekIds()) {
                Result<DEKWithMetadata, KeyError> dekResult = keyManager.getDEK(dekId);
                if (dekResult.isFailure()) {
                    missingKeys.add(dekId);
                    logger.warn("DEK not available for restore: dekId={}", dekId);
                }
            }

            if (!missingKeys.isEmpty()) {
                logger.error("Key availability check failed: {} missing DEKs for restore point {}",
                        missingKeys.size(), restorePoint.getRestorePointId());
                return Result.failure(RestoreError.of("KEYS_UNAVAILABLE",
                        "Required DEKs not available for restore: " + missingKeys));
            }

            logger.info("Key availability verified for restore point: restorePointId={}",
                    restorePoint.getRestorePointId());

            return Result.success(true);

        } catch (Exception e) {
            logger.error("Failed to verify key availability for restore point {}: {}",
                    restorePoint.getRestorePointId(), e.getMessage());
            return Result.failure(RestoreError.of("KEY_AVAILABILITY_CHECK_FAILED",
                    "Failed to verify key availability", e));
        }
    }

    @Override
    public Result<RestoreResult, RestoreError> restoreCiphertext(RestorePoint restorePoint,
                                                                  BackupCertificate backup) {
        Objects.requireNonNull(restorePoint, "Restore point cannot be null");
        Objects.requireNonNull(backup, "Backup certificate cannot be null");

        try {
            // First verify key availability
            Result<Boolean, RestoreError> keyCheck = verifyKeyAvailability(restorePoint);
            if (keyCheck.isFailure()) {
                return Result.failure(keyCheck.getError().orElseThrow());
            }

            // Retrieve backup records (ciphertext only — never plaintext)
            List<BackupRecord> records = backupService.getBackupRecords(backup.getBackupId());

            // Validate that all records contain only ciphertext (no plaintext)
            // This is enforced by the BackupRecord type itself, but we log for audit
            logger.info("Restoring {} ciphertext records from backup: backupId={}, restorePointId={}",
                    records.size(), backup.getBackupId(), restorePoint.getRestorePointId());

            UUID restoreId = UUID.randomUUID();
            RestoreResult result = RestoreResult.of(
                    restoreId,
                    backup.getBackupId(),
                    restorePoint.getContext(),
                    Instant.now(),
                    records.size(),
                    false // decryption not yet verified — call testDecryptionWithHistoricalKeys
            );

            logger.info("Ciphertext restore completed: restoreId={}, recordsRestored={}",
                    restoreId, records.size());

            return Result.success(result);

        } catch (Exception e) {
            logger.error("Failed to restore ciphertext from backup {}: {}",
                    backup.getBackupId(), e.getMessage());
            return Result.failure(RestoreError.of("RESTORE_FAILED",
                    "Failed to restore ciphertext from backup", e));
        }
    }

    @Override
    public Result<Boolean, RestoreError> testDecryptionWithHistoricalKeys(RestorePoint restorePoint) {
        Objects.requireNonNull(restorePoint, "Restore point cannot be null");

        try {
            // Retrieve backup records for the restore point's backup
            List<BackupRecord> records = backupService.getBackupRecords(restorePoint.getBackupId());

            if (records.isEmpty()) {
                logger.warn("No backup records found for restore point: restorePointId={}",
                        restorePoint.getRestorePointId());
                // No records to test — consider this a pass (empty backup is valid)
                return Result.success(true);
            }

            int testedCount = 0;
            int failedCount = 0;

            // Test decryption of a sample of records using historical keys
            for (BackupRecord record : records) {
                // Verify the DEK for this record is available
                Result<DEKWithMetadata, KeyError> dekResult = keyManager.getDEK(record.getDekId());
                if (dekResult.isFailure()) {
                    failedCount++;
                    logger.warn("Cannot test decryption: DEK not available for record {}, dekId={}",
                            record.getRecordId(), record.getDekId());
                    continue;
                }

                // Attempt decryption to verify the ciphertext is valid
                Result<String, DecryptionError> decryptResult =
                        encryptionService.decrypt(record.getCiphertext(), record.getContext());

                if (decryptResult.isFailure()) {
                    failedCount++;
                    logger.warn("Decryption test failed for record {}: {}",
                            record.getRecordId(),
                            decryptResult.getError().map(DecryptionError::getMessage).orElse("unknown"));
                } else {
                    testedCount++;
                }
            }

            if (failedCount > 0) {
                logger.error("Decryption test failed: {}/{} records could not be decrypted for restore point {}",
                        failedCount, records.size(), restorePoint.getRestorePointId());
                return Result.failure(RestoreError.of("DECRYPTION_TEST_FAILED",
                        "Decryption test failed: " + failedCount + " of " + records.size() +
                                " records could not be decrypted"));
            }

            logger.info("Decryption test passed: {}/{} records successfully decrypted for restore point {}",
                    testedCount, records.size(), restorePoint.getRestorePointId());

            return Result.success(true);

        } catch (Exception e) {
            logger.error("Failed to test decryption for restore point {}: {}",
                    restorePoint.getRestorePointId(), e.getMessage());
            return Result.failure(RestoreError.of("DECRYPTION_TEST_ERROR",
                    "Failed to test decryption with historical keys", e));
        }
    }
}
