package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Value object representing a restore point with timestamp and required key versions.
 *
 * <p>A restore point identifies a specific point in time from which data can be
 * restored. It includes the DEK versions that were active at that time, which are
 * required to decrypt the backup records.
 */
public final class RestorePoint {

    private final UUID restorePointId;
    private final Instant targetTimestamp;
    private final BoundedContext context;
    private final List<UUID> requiredDekIds;
    private final UUID backupId;

    private RestorePoint(UUID restorePointId, Instant targetTimestamp, BoundedContext context,
                         List<UUID> requiredDekIds, UUID backupId) {
        this.restorePointId = Objects.requireNonNull(restorePointId, "Restore point ID cannot be null");
        this.targetTimestamp = Objects.requireNonNull(targetTimestamp, "Target timestamp cannot be null");
        this.context = Objects.requireNonNull(context, "Context cannot be null");
        this.requiredDekIds = Collections.unmodifiableList(
                Objects.requireNonNull(requiredDekIds, "Required DEK IDs cannot be null"));
        this.backupId = Objects.requireNonNull(backupId, "Backup ID cannot be null");
    }

    public static RestorePoint of(UUID restorePointId, Instant targetTimestamp, BoundedContext context,
                                  List<UUID> requiredDekIds, UUID backupId) {
        return new RestorePoint(restorePointId, targetTimestamp, context, requiredDekIds, backupId);
    }

    public UUID getRestorePointId() {
        return restorePointId;
    }

    public Instant getTargetTimestamp() {
        return targetTimestamp;
    }

    public BoundedContext getContext() {
        return context;
    }

    /**
     * Returns the DEK IDs required to decrypt the backup records at this restore point.
     * All of these DEKs must be available for the restore to succeed.
     */
    public List<UUID> getRequiredDekIds() {
        return requiredDekIds;
    }

    public UUID getBackupId() {
        return backupId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RestorePoint that = (RestorePoint) o;
        return Objects.equals(restorePointId, that.restorePointId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(restorePointId);
    }

    @Override
    public String toString() {
        return "RestorePoint{restorePointId=" + restorePointId +
                ", targetTimestamp=" + targetTimestamp +
                ", context=" + context +
                ", requiredDekCount=" + requiredDekIds.size() +
                ", backupId=" + backupId + "}";
    }
}
