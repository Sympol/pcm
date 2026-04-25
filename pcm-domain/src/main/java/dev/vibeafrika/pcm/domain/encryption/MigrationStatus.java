package dev.vibeafrika.pcm.domain.encryption;

/**
 * Represents the lifecycle status of an algorithm migration.
 */
public enum MigrationStatus {
    /** Migration has been created but not yet started. */
    PENDING,
    /** Migration is actively routing traffic to the new algorithm. */
    IN_PROGRESS,
    /** Migration has been fully completed; all traffic uses the new algorithm. */
    COMPLETED,
    /** Migration was rolled back to the previous algorithm. */
    ROLLED_BACK,
    /** Migration encountered an unrecoverable error. */
    FAILED
}
