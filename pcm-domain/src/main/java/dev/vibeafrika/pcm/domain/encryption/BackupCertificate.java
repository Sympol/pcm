package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Value object representing a completed backup with metadata.
 *
 * <p>A backup certificate proves that a backup was completed successfully and
 * contains metadata needed to restore from the backup, including the key versions
 * that were active at the time of the backup.
 *
 * <p>The backup certificate itself does NOT contain any plaintext PII or key material.
 */
public final class BackupCertificate {

    private final UUID backupId;
    private final BoundedContext context;
    private final Instant backupTimestamp;
    private final List<UUID> dekIdsAtBackupTime;
    private final int recordCount;
    private final String signature;

    private BackupCertificate(UUID backupId, BoundedContext context, Instant backupTimestamp,
                              List<UUID> dekIdsAtBackupTime, int recordCount, String signature) {
        this.backupId = Objects.requireNonNull(backupId, "Backup ID cannot be null");
        this.context = Objects.requireNonNull(context, "Context cannot be null");
        this.backupTimestamp = Objects.requireNonNull(backupTimestamp, "Backup timestamp cannot be null");
        this.dekIdsAtBackupTime = Collections.unmodifiableList(
                Objects.requireNonNull(dekIdsAtBackupTime, "DEK IDs cannot be null"));
        this.recordCount = recordCount;
        this.signature = Objects.requireNonNull(signature, "Signature cannot be null");
    }

    public static BackupCertificate of(UUID backupId, BoundedContext context, Instant backupTimestamp,
                                       List<UUID> dekIdsAtBackupTime, int recordCount, String signature) {
        return new BackupCertificate(backupId, context, backupTimestamp,
                dekIdsAtBackupTime, recordCount, signature);
    }

    public UUID getBackupId() {
        return backupId;
    }

    public BoundedContext getContext() {
        return context;
    }

    public Instant getBackupTimestamp() {
        return backupTimestamp;
    }

    /**
     * Returns the DEK IDs that were active at the time of the backup.
     * These DEKs are required to decrypt the backup records.
     */
    public List<UUID> getDekIdsAtBackupTime() {
        return dekIdsAtBackupTime;
    }

    public int getRecordCount() {
        return recordCount;
    }

    /** HMAC signature for integrity verification of this certificate. */
    public String getSignature() {
        return signature;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BackupCertificate that = (BackupCertificate) o;
        return Objects.equals(backupId, that.backupId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(backupId);
    }

    @Override
    public String toString() {
        return "BackupCertificate{backupId=" + backupId +
                ", context=" + context +
                ", backupTimestamp=" + backupTimestamp +
                ", dekCount=" + dekIdsAtBackupTime.size() +
                ", recordCount=" + recordCount + "}";
    }
}
