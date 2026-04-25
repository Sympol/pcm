package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Objects;

/**
 * Value object representing the state of an in-progress algorithm migration.
 *
 * <p>Captures the source and target algorithms, the current rollout percentage,
 * the time the migration started (used to enforce the 24-hour rollback window),
 * and the current lifecycle status.
 */
public final class AlgorithmMigrationRecord {

    private final MigrationId migrationId;
    private final EncryptionAlgorithm fromAlgorithm;
    private final EncryptionAlgorithm toAlgorithm;
    private final int rolloutPercentage;
    private final Instant startedAt;
    private final MigrationStatus status;

    private AlgorithmMigrationRecord(
            MigrationId migrationId,
            EncryptionAlgorithm fromAlgorithm,
            EncryptionAlgorithm toAlgorithm,
            int rolloutPercentage,
            Instant startedAt,
            MigrationStatus status) {
        this.migrationId = Objects.requireNonNull(migrationId, "migrationId cannot be null");
        this.fromAlgorithm = Objects.requireNonNull(fromAlgorithm, "fromAlgorithm cannot be null");
        this.toAlgorithm = Objects.requireNonNull(toAlgorithm, "toAlgorithm cannot be null");
        this.rolloutPercentage = rolloutPercentage;
        this.startedAt = Objects.requireNonNull(startedAt, "startedAt cannot be null");
        this.status = Objects.requireNonNull(status, "status cannot be null");
    }

    public static AlgorithmMigrationRecord create(
            MigrationId migrationId,
            EncryptionAlgorithm fromAlgorithm,
            EncryptionAlgorithm toAlgorithm,
            int rolloutPercentage,
            Instant startedAt) {
        return new AlgorithmMigrationRecord(
                migrationId, fromAlgorithm, toAlgorithm,
                rolloutPercentage, startedAt, MigrationStatus.IN_PROGRESS);
    }

    /** Returns a copy of this record with an updated rollout percentage. */
    public AlgorithmMigrationRecord withRolloutPercentage(int newPercentage) {
        return new AlgorithmMigrationRecord(
                migrationId, fromAlgorithm, toAlgorithm,
                newPercentage, startedAt, status);
    }

    /** Returns a copy of this record with an updated status. */
    public AlgorithmMigrationRecord withStatus(MigrationStatus newStatus) {
        return new AlgorithmMigrationRecord(
                migrationId, fromAlgorithm, toAlgorithm,
                rolloutPercentage, startedAt, newStatus);
    }

    public MigrationId getMigrationId() { return migrationId; }
    public EncryptionAlgorithm getFromAlgorithm() { return fromAlgorithm; }
    public EncryptionAlgorithm getToAlgorithm() { return toAlgorithm; }
    public int getRolloutPercentage() { return rolloutPercentage; }
    public Instant getStartedAt() { return startedAt; }
    public MigrationStatus getStatus() { return status; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AlgorithmMigrationRecord that = (AlgorithmMigrationRecord) o;
        return rolloutPercentage == that.rolloutPercentage
                && Objects.equals(migrationId, that.migrationId)
                && fromAlgorithm == that.fromAlgorithm
                && toAlgorithm == that.toAlgorithm
                && Objects.equals(startedAt, that.startedAt)
                && status == that.status;
    }

    @Override
    public int hashCode() {
        return Objects.hash(migrationId, fromAlgorithm, toAlgorithm,
                rolloutPercentage, startedAt, status);
    }

    @Override
    public String toString() {
        return "AlgorithmMigrationRecord{"
                + "migrationId=" + migrationId
                + ", fromAlgorithm=" + fromAlgorithm
                + ", toAlgorithm=" + toAlgorithm
                + ", rolloutPercentage=" + rolloutPercentage
                + ", startedAt=" + startedAt
                + ", status=" + status
                + '}';
    }
}
