package dev.vibeafrika.pcm.domain.encryption;

/**
 * Represents errors that can occur during algorithm migration operations.
 */
public enum MigrationError {
    /** No migration exists for the given MigrationId. */
    MIGRATION_NOT_FOUND,
    /** The rollout percentage is not between 0 and 100 (inclusive). */
    INVALID_ROLLOUT_PERCENTAGE,
    /** Rollback was requested but the 24-hour rollback window has expired. */
    ROLLBACK_WINDOW_EXPIRED,
    /** A migration between the same algorithm pair is already active. */
    MIGRATION_ALREADY_ACTIVE
}
