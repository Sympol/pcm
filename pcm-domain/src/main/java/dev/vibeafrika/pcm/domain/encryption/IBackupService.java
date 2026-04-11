package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.List;

/**
 * Domain interface for backup operations.
 *
 * <p>The BackupService is responsible for:
 * <ul>
 *   <li>Creating backups that contain only ciphertext — never plaintext PII</li>
 *   <li>Exporting KEKs encrypted with an offline master key for cold storage</li>
 *   <li>Maintaining key version history so historical backups can be decrypted</li>
 *   <li>Continuously backing up audit logs</li>
 * </ul>
 *
 * <p>Security guarantees:
 * <ul>
 *   <li>Backup records NEVER contain plaintext PII — only ciphertext</li>
 *   <li>KEKs exported for backup are encrypted with an offline master key</li>
 *   <li>Key version history is maintained to enable decryption of historical backups</li>
 * </ul>
 */
public interface IBackupService {

    /**
     * Creates a backup of all encrypted records for the given bounded context.
     *
     * <p>The backup contains ONLY ciphertext — never plaintext PII. The backup
     * certificate records which DEK versions were active at backup time so that
     * the backup can be decrypted during a restore operation.
     *
     * @param context   the bounded context to back up
     * @param timestamp the timestamp at which the backup is taken
     * @return Result containing a BackupCertificate on success, or BackupError on failure
     */
    Result<BackupCertificate, BackupError> createBackup(BoundedContext context, Instant timestamp);

    /**
     * Exports all KEKs for the given environment, encrypted with the specified offline master key.
     *
     * <p>The offline master key is stored in a hardware security module or secure offline storage.
     * This export enables disaster recovery when the primary KMS is unavailable.
     *
     * @param offlineMasterKeyId the ID of the offline master key to use for encrypting the KEKs
     * @return Result containing a KeyExportBundle on success, or BackupError on failure
     */
    Result<KeyExportBundle, BackupError> exportKEKsWithOfflineMasterKey(String offlineMasterKeyId);

    /**
     * Retrieves the key version history for the given bounded context.
     *
     * <p>Key version history maps DEK IDs to their active time ranges, enabling
     * decryption of historical backups with the correct key version.
     *
     * @param context the bounded context for which to retrieve key version history
     * @return Result containing a list of KeyVersionHistory entries, or BackupError on failure
     */
    Result<List<KeyVersionHistory>, BackupError> getKeyVersionHistory(BoundedContext context);

    /**
     * Backs up audit logs for the given time range.
     *
     * <p>Audit logs are backed up continuously to ensure they are available for
     * compliance and forensic analysis even if the primary audit log store is lost (Req 30.5).
     *
     * @param from the start of the time range (inclusive)
     * @param to   the end of the time range (inclusive)
     * @return Result containing void on success, or BackupError on failure
     */
    Result<Void, BackupError> backupAuditLogs(Instant from, Instant to);
}
