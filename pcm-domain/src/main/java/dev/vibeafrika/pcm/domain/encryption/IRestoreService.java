package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;

/**
 * Domain interface for restore operations.
 *
 * <p>The RestoreService is responsible for:
 * <ul>
 *   <li>Identifying the restore point and required key versions for a target timestamp</li>
 *   <li>Verifying that the required key versions are available before restoring</li>
 *   <li>Restoring ciphertext from backup (ciphertext only — never plaintext)</li>
 *   <li>Testing decryption with historical keys to validate restore integrity</li>
 * </ul>
 *
 * <p>Security guarantees:
 * <ul>
 *   <li>Restore operations work with ciphertext only — plaintext is never stored in backups</li>
 *   <li>Key availability is verified before restore to prevent partial restores</li>
 *   <li>Decryption is tested after restore to confirm data integrity</li>
 * </ul>
 */
public interface IRestoreService {

    /**
     * Identifies the restore point for the given target timestamp.
     *
     * <p>This method determines which backup to use and which DEK versions were
     * active at the target timestamp. The restore point contains all information
     * needed to perform the restore.
     *
     * @param targetTimestamp the point in time to restore to
     * @return Result containing a RestorePoint on success, or RestoreError on failure
     */
    Result<RestorePoint, RestoreError> identifyRestorePoint(Instant targetTimestamp);

    /**
     * Verifies that all required key versions are available for the given restore point.
     *
     * <p>Before performing a restore, this method checks that all DEKs referenced
     * in the restore point are accessible. If any DEK is missing, the restore cannot
     * proceed.
     *
     * @param restorePoint the restore point to verify key availability for
     * @return Result containing true if all keys are available, or RestoreError on failure
     */
    Result<Boolean, RestoreError> verifyKeyAvailability(RestorePoint restorePoint);

    /**
     * Restores ciphertext from the backup identified by the restore point.
     *
     * <p>This method restores the encrypted records from the backup. The restored
     * data is ciphertext only — no plaintext PII is stored in the backup or
     * returned by this method.
     *
     * @param restorePoint the restore point identifying which backup to restore from
     * @param backup       the backup certificate identifying the backup to restore
     * @return Result containing a RestoreResult on success, or RestoreError on failure
     */
    Result<RestoreResult, RestoreError> restoreCiphertext(RestorePoint restorePoint,
                                                          BackupCertificate backup);

    /**
     * Tests decryption with historical keys to validate restore integrity.
     *
     * <p>After restoring ciphertext, this method verifies that the restored data
     * can be decrypted using the historical DEKs. This confirms that the restore
     * was successful and the data is intact.
     *
     * @param restorePoint the restore point containing the required DEK versions
     * @return Result containing true if decryption succeeds, or RestoreError on failure
     */
    Result<Boolean, RestoreError> testDecryptionWithHistoricalKeys(RestorePoint restorePoint);
}
