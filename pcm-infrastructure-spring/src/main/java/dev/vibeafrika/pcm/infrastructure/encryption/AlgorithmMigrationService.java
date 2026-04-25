package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.AlgorithmMigrationRecord;
import dev.vibeafrika.pcm.domain.encryption.EncryptionAlgorithm;
import dev.vibeafrika.pcm.domain.encryption.IAlgorithmMigrationService;
import dev.vibeafrika.pcm.domain.encryption.MigrationError;
import dev.vibeafrika.pcm.domain.encryption.MigrationId;
import dev.vibeafrika.pcm.domain.encryption.MigrationStatus;
import dev.vibeafrika.pcm.domain.encryption.Result;
import dev.vibeafrika.pcm.domain.encryption.Unit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Infrastructure implementation of {@link IAlgorithmMigrationService}.
 *
 * <p>Supports parallel operation of old and new encryption algorithms during migration,
 * with gradual traffic rollout and a 24-hour rollback window.
 *
 * <p>Migration state is stored in-memory using a {@link ConcurrentHashMap}.
 * This is intentional — migration state is operational metadata, not persistent data.
 *
 * <p>Traffic routing: for each encryption operation, {@link ThreadLocalRandom} is used
 * to decide whether to use the new algorithm. If {@code random < rolloutPercentage / 100.0},
 * the new algorithm is selected; otherwise the old algorithm is used.
 *
 */
public class AlgorithmMigrationService implements IAlgorithmMigrationService {

    private static final Logger logger = LoggerFactory.getLogger(AlgorithmMigrationService.class);

    /** Maximum allowed rollback window after migration start. */
    private static final Duration ROLLBACK_WINDOW = Duration.ofHours(24);

    /** In-memory store of all migrations, keyed by MigrationId. */
    private final ConcurrentHashMap<MigrationId, AlgorithmMigrationRecord> migrations =
            new ConcurrentHashMap<>();

    // =========================================================================
    // IAlgorithmMigrationService implementation
    // =========================================================================

    /**
     * {@inheritDoc}
     *
     * <p>Validates that the rollout percentage is between 0 and 100, and that no active
     * migration already exists for the same algorithm pair.
     */
    @Override
    public Result<MigrationId, MigrationError> startMigration(
            EncryptionAlgorithm fromAlgorithm,
            EncryptionAlgorithm toAlgorithm,
            int rolloutPercentage) {

        if (!isValidPercentage(rolloutPercentage)) {
            logger.warn("startMigration rejected: invalid rollout percentage {} for {} -> {}",
                    rolloutPercentage, fromAlgorithm, toAlgorithm);
            return Result.failure(MigrationError.INVALID_ROLLOUT_PERCENTAGE);
        }

        // Check for an already-active migration between the same algorithm pair
        boolean alreadyActive = migrations.values().stream()
                .anyMatch(r -> r.getFromAlgorithm() == fromAlgorithm
                        && r.getToAlgorithm() == toAlgorithm
                        && r.getStatus() == MigrationStatus.IN_PROGRESS);

        if (alreadyActive) {
            logger.warn("startMigration rejected: active migration already exists for {} -> {}",
                    fromAlgorithm, toAlgorithm);
            return Result.failure(MigrationError.MIGRATION_ALREADY_ACTIVE);
        }

        MigrationId id = MigrationId.generate();
        AlgorithmMigrationRecord record = AlgorithmMigrationRecord.create(
                id, fromAlgorithm, toAlgorithm, rolloutPercentage, Instant.now());
        migrations.put(id, record);

        logger.info("Migration started: id={}, from={}, to={}, rollout={}%",
                id, fromAlgorithm, toAlgorithm, rolloutPercentage);
        logAlgorithmUsageMetrics(record);

        return Result.success(id);
    }

    /** {@inheritDoc} */
    @Override
    public Result<Integer, MigrationError> getRolloutPercentage(MigrationId migrationId) {
        AlgorithmMigrationRecord record = migrations.get(migrationId);
        if (record == null) {
            return Result.failure(MigrationError.MIGRATION_NOT_FOUND);
        }
        return Result.success(record.getRolloutPercentage());
    }

    /**
     * {@inheritDoc}
     *
     * <p>Validates that the percentage is between 0 and 100 and that the migration exists.
     */
    @Override
    public Result<Unit, MigrationError> updateRolloutPercentage(MigrationId migrationId, int percentage) {
        if (!isValidPercentage(percentage)) {
            logger.warn("updateRolloutPercentage rejected: invalid percentage {} for migration {}",
                    percentage, migrationId);
            return Result.failure(MigrationError.INVALID_ROLLOUT_PERCENTAGE);
        }

        AlgorithmMigrationRecord existing = migrations.get(migrationId);
        if (existing == null) {
            return Result.failure(MigrationError.MIGRATION_NOT_FOUND);
        }

        AlgorithmMigrationRecord updated = existing.withRolloutPercentage(percentage);
        migrations.put(migrationId, updated);

        logger.info("Migration rollout updated: id={}, from={}, to={}, rollout={}%",
                migrationId, updated.getFromAlgorithm(), updated.getToAlgorithm(), percentage);
        logAlgorithmUsageMetrics(updated);

        return Result.success(Unit.unit());
    }

    /**
     * {@inheritDoc}
     *
     * <p>Rollback is only permitted within 24 hours of migration start.
     */
    @Override
    public Result<Unit, MigrationError> rollback(MigrationId migrationId) {
        AlgorithmMigrationRecord record = migrations.get(migrationId);
        if (record == null) {
            return Result.failure(MigrationError.MIGRATION_NOT_FOUND);
        }

        Duration elapsed = Duration.between(record.getStartedAt(), Instant.now());
        if (elapsed.compareTo(ROLLBACK_WINDOW) > 0) {
            logger.warn("Rollback rejected for migration {}: rollback window expired (elapsed={})",
                    migrationId, elapsed);
            return Result.failure(MigrationError.ROLLBACK_WINDOW_EXPIRED);
        }

        AlgorithmMigrationRecord rolledBack = record.withStatus(MigrationStatus.ROLLED_BACK);
        migrations.put(migrationId, rolledBack);

        logger.info("Migration rolled back: id={}, from={}, to={}, elapsed={}",
                migrationId, record.getFromAlgorithm(), record.getToAlgorithm(), elapsed);
        logAlgorithmUsageMetrics(rolledBack);

        return Result.success(Unit.unit());
    }

    /** {@inheritDoc} */
    @Override
    public Result<MigrationStatus, MigrationError> getMigrationStatus(MigrationId migrationId) {
        AlgorithmMigrationRecord record = migrations.get(migrationId);
        if (record == null) {
            return Result.failure(MigrationError.MIGRATION_NOT_FOUND);
        }
        return Result.success(record.getStatus());
    }

    // =========================================================================
    // Traffic routing
    // =========================================================================

    /**
     * Determines which algorithm to use for an encryption operation based on the
     * current rollout percentage of the active migration.
     *
     * <p>If no active migration exists for the given algorithm, the {@code defaultAlgorithm}
     * is returned. Otherwise, {@link ThreadLocalRandom} is used to route traffic:
     * if {@code random < rolloutPercentage / 100.0}, the new algorithm is selected.
     *
     * @param defaultAlgorithm the algorithm to use when no migration is active
     * @return the algorithm to use for this operation
     */
    public EncryptionAlgorithm selectAlgorithm(EncryptionAlgorithm defaultAlgorithm) {
        AlgorithmMigrationRecord activeMigration = migrations.values().stream()
                .filter(r -> r.getFromAlgorithm() == defaultAlgorithm
                        && r.getStatus() == MigrationStatus.IN_PROGRESS)
                .findFirst()
                .orElse(null);

        if (activeMigration == null) {
            return defaultAlgorithm;
        }

        double roll = ThreadLocalRandom.current().nextDouble();
        double threshold = activeMigration.getRolloutPercentage() / 100.0;
        boolean useNew = roll < threshold;

        EncryptionAlgorithm selected = useNew
                ? activeMigration.getToAlgorithm()
                : activeMigration.getFromAlgorithm();

        logger.debug("Algorithm selected: migration={}, algorithm={}, roll={}, threshold={}",
                activeMigration.getMigrationId(), selected, roll, threshold);

        logAlgorithmUsageMetrics(activeMigration, selected, useNew);

        return selected;
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    private static boolean isValidPercentage(int percentage) {
        return percentage >= 0 && percentage <= 100;
    }

    /**
     * Logs algorithm usage metrics for a migration state change.
     */
    private void logAlgorithmUsageMetrics(AlgorithmMigrationRecord record) {
        logger.info("Algorithm migration metrics: id={}, from={}, to={}, rollout={}%, status={}",
                record.getMigrationId(),
                record.getFromAlgorithm(),
                record.getToAlgorithm(),
                record.getRolloutPercentage(),
                record.getStatus());
    }

    /**
     * Logs algorithm usage metrics for a single routing decision.
     */
    private void logAlgorithmUsageMetrics(
            AlgorithmMigrationRecord record,
            EncryptionAlgorithm selected,
            boolean usedNewAlgorithm) {
        logger.info("Algorithm routing: migration={}, selected={}, usedNew={}, rollout={}%",
                record.getMigrationId(),
                selected,
                usedNewAlgorithm,
                record.getRolloutPercentage());
    }
}
