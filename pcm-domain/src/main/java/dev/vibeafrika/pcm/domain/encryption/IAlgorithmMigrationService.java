package dev.vibeafrika.pcm.domain.encryption;

/**
 * Domain interface for managing cryptographic algorithm migrations.
 *
 * <p>Supports the gradual, reversible migration from one encryption algorithm to another
 * as required by Cryptographic Change Management.
 *
 * <p>Key capabilities:
 * <ul>
 *   <li>Parallel operation of old and new algorithms during migration</li>
 *   <li>Gradual rollout starting at 1% of traffic</li>
 *   <li>Rollback to the previous algorithm within 24 hours</li>
 *   <li>Algorithm usage metrics logging during migration</li>
 * </ul>
 */
public interface IAlgorithmMigrationService {

    /**
     * Starts a new algorithm migration from {@code fromAlgorithm} to {@code toAlgorithm}
     * at the specified initial rollout percentage.
     *
     * <p>The recommended starting rollout is 1%. Only one active migration
     * per algorithm pair is allowed at a time.
     *
     * @param fromAlgorithm      the algorithm currently in use
     * @param toAlgorithm        the algorithm to migrate to
     * @param rolloutPercentage  initial percentage of traffic to route to the new algorithm (0–100)
     * @return Result containing the new {@link MigrationId}, or {@link MigrationError} on failure
     */
    Result<MigrationId, MigrationError> startMigration(
            EncryptionAlgorithm fromAlgorithm,
            EncryptionAlgorithm toAlgorithm,
            int rolloutPercentage);

    /**
     * Returns the current rollout percentage for the given migration.
     *
     * @param migrationId the migration to query
     * @return Result containing the rollout percentage (0–100), or {@link MigrationError} on failure
     */
    Result<Integer, MigrationError> getRolloutPercentage(MigrationId migrationId);

    /**
     * Updates the rollout percentage for an active migration.
     *
     * <p>Allows operators to gradually increase (or decrease) the percentage of traffic
     * routed to the new algorithm.
     *
     * @param migrationId  the migration to update
     * @param percentage   the new rollout percentage (0–100)
     * @return Result containing {@link Unit} on success, or {@link MigrationError} on failure
     */
    Result<Unit, MigrationError> updateRolloutPercentage(MigrationId migrationId, int percentage);

    /**
     * Rolls back the migration to the previous algorithm.
     *
     * <p>Rollback is only permitted within 24 hours of migration start.
     *
     * @param migrationId the migration to roll back
     * @return Result containing {@link Unit} on success, or {@link MigrationError} on failure
     */
    Result<Unit, MigrationError> rollback(MigrationId migrationId);

    /**
     * Returns the current status of the given migration.
     *
     * @param migrationId the migration to query
     * @return Result containing the {@link MigrationStatus}, or {@link MigrationError} on failure
     */
    Result<MigrationStatus, MigrationError> getMigrationStatus(MigrationId migrationId);
}
