package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Value object representing the result of a restore operation.
 *
 * <p>A restore result contains metadata about the completed restore, including
 * how many records were restored and whether decryption was verified.
 *
 * <p>The restore result does NOT contain any plaintext PII — only metadata about
 * the restore operation.
 */
public final class RestoreResult {

    private final UUID restoreId;
    private final UUID backupId;
    private final BoundedContext context;
    private final Instant restoredAt;
    private final int recordsRestored;
    private final boolean decryptionVerified;

    private RestoreResult(UUID restoreId, UUID backupId, BoundedContext context,
                          Instant restoredAt, int recordsRestored, boolean decryptionVerified) {
        this.restoreId = Objects.requireNonNull(restoreId, "Restore ID cannot be null");
        this.backupId = Objects.requireNonNull(backupId, "Backup ID cannot be null");
        this.context = Objects.requireNonNull(context, "Context cannot be null");
        this.restoredAt = Objects.requireNonNull(restoredAt, "Restored timestamp cannot be null");
        this.recordsRestored = recordsRestored;
        this.decryptionVerified = decryptionVerified;
    }

    public static RestoreResult of(UUID restoreId, UUID backupId, BoundedContext context,
                                   Instant restoredAt, int recordsRestored, boolean decryptionVerified) {
        return new RestoreResult(restoreId, backupId, context, restoredAt,
                recordsRestored, decryptionVerified);
    }

    public UUID getRestoreId() {
        return restoreId;
    }

    public UUID getBackupId() {
        return backupId;
    }

    public BoundedContext getContext() {
        return context;
    }

    public Instant getRestoredAt() {
        return restoredAt;
    }

    public int getRecordsRestored() {
        return recordsRestored;
    }

    /**
     * Returns true if decryption was verified after restore.
     * Decryption verification confirms that the restored ciphertext can be
     * decrypted with the historical keys.
     */
    public boolean isDecryptionVerified() {
        return decryptionVerified;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RestoreResult that = (RestoreResult) o;
        return Objects.equals(restoreId, that.restoreId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(restoreId);
    }

    @Override
    public String toString() {
        return "RestoreResult{restoreId=" + restoreId +
                ", backupId=" + backupId +
                ", context=" + context +
                ", restoredAt=" + restoredAt +
                ", recordsRestored=" + recordsRestored +
                ", decryptionVerified=" + decryptionVerified + "}";
    }
}
