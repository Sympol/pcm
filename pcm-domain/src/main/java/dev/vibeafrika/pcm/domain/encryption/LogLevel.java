package dev.vibeafrika.pcm.domain.encryption;

/**
 * Audit logging levels for the {@link IAuditLogger}.
 *
 * <p>Levels are ordered from most to least severe:
 * <ol>
 *   <li>{@link #CRITICAL} – sensitive operations that must always be logged
 *       (key rotation, access failures). Cannot be filtered out.</li>
 *   <li>{@link #HIGH} – important security events such as authentication failures.</li>
 *   <li>{@link #MEDIUM} – normal operational events (encryption, decryption).</li>
 *   <li>{@link #LOW} – verbose/diagnostic events (key cache hits, etc.).</li>
 * </ol>
 *
 * <p>When a minimum level is configured, only events at or above that level are
 * logged – EXCEPT for {@link #CRITICAL} events which are ALWAYS logged regardless
 * of configuration.
 */
public enum LogLevel {

    /** Highest severity – always logged regardless of configured minimum level. */
    CRITICAL(4),

    /** High severity – authentication failures and important security events. */
    HIGH(3),

    /** Medium severity – normal encryption/decryption operations. */
    MEDIUM(2),

    /** Low severity – verbose/diagnostic events subject to sampling. */
    LOW(1);

    private final int numericLevel;

    LogLevel(int numericLevel) {
        this.numericLevel = numericLevel;
    }

    /**
     * Returns {@code true} if this level is at or above the given minimum level.
     * CRITICAL always returns {@code true}.
     *
     * @param minimumLevel the configured minimum level
     * @return {@code true} if this event should be logged
     */
    public boolean isAtLeast(LogLevel minimumLevel) {
        if (this == CRITICAL) {
            return true; // CRITICAL is always logged
        }
        return this.numericLevel >= minimumLevel.numericLevel;
    }
}
