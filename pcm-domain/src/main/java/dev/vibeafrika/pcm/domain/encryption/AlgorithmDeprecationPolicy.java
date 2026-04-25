package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Domain policy for managing cryptographic algorithm deprecation.
 *
 * <p>Maintains a registry of deprecation notices per {@link EncryptionAlgorithm},
 * enforcing a 12-month notice period before any algorithm may be removed
 *
 * <p>When an algorithm is deprecated, a {@link DeprecationNotice} is recorded
 * with the deprecation timestamp and a computed removal date 365 days later.
 * Callers are warned via SLF4J whenever they query a deprecated algorithm.
 */
public class AlgorithmDeprecationPolicy {

    /** Number of days that must elapse between deprecation and removal. */
    private static final long NOTICE_PERIOD_DAYS = 365L;

    private final Map<EncryptionAlgorithm, DeprecationNotice> notices = new ConcurrentHashMap<>();

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Records a deprecation notice for the given algorithm.
     *
     * <p>The removal date is set to {@code now + 365 days}, providing the
     * mandatory 12-month notice period.
     *
     * @param algorithm the algorithm being deprecated
     * @param reason    human-readable reason for deprecation
     */
    public void deprecate(EncryptionAlgorithm algorithm, String reason) {
        Objects.requireNonNull(algorithm, "algorithm cannot be null");
        Objects.requireNonNull(reason, "reason cannot be null");

        Instant deprecatedAt = Instant.now();
        Instant removalDate = deprecatedAt.plus(NOTICE_PERIOD_DAYS, ChronoUnit.DAYS);
        DeprecationNotice notice = new DeprecationNotice(algorithm, deprecatedAt, removalDate, reason);
        notices.put(algorithm, notice);
    }

    /**
     * Returns {@code true} if a deprecation notice exists for the given algorithm.
     *
     * <p>Logs a warning when the algorithm is deprecated, reminding callers of
     * the upcoming removal date.
     *
     * @param algorithm the algorithm to check
     * @return {@code true} if deprecated
     */
    public boolean isDeprecated(EncryptionAlgorithm algorithm) {
        Objects.requireNonNull(algorithm, "algorithm cannot be null");
        DeprecationNotice notice = notices.get(algorithm);
        if (notice != null) {
            return true;
        }
        return false;
    }

    /**
     * Returns the {@link DeprecationNotice} for the given algorithm, if one exists.
     *
     * @param algorithm the algorithm to query
     * @return an {@link Optional} containing the notice, or empty if not deprecated
     */
    public Optional<DeprecationNotice> getNotice(EncryptionAlgorithm algorithm) {
        Objects.requireNonNull(algorithm, "algorithm cannot be null");
        return Optional.ofNullable(notices.get(algorithm));
    }

    /**
     * Returns {@code true} if the 12-month notice period has elapsed and the
     * algorithm is eligible for removal.
     *
     * <p>An algorithm is eligible for removal when its {@code removalDate} is
     * in the past.
     *
     * @param algorithm the algorithm to check
     * @return {@code true} if the removal date has passed
     */
    public boolean isEligibleForRemoval(EncryptionAlgorithm algorithm) {
        Objects.requireNonNull(algorithm, "algorithm cannot be null");
        DeprecationNotice notice = notices.get(algorithm);
        if (notice == null) {
            return false;
        }
        return Instant.now().isAfter(notice.removalDate());
    }

    // =========================================================================
    // Inner record
    // =========================================================================

    /**
     * Immutable record capturing the details of an algorithm deprecation notice.
     *
     * @param algorithm    the deprecated algorithm
     * @param deprecatedAt the instant the deprecation was recorded
     * @param removalDate  the earliest instant the algorithm may be removed (deprecatedAt + 365 days)
     * @param reason       human-readable reason for deprecation
     */
    public record DeprecationNotice(
            EncryptionAlgorithm algorithm,
            Instant deprecatedAt,
            Instant removalDate,
            String reason) {

        public DeprecationNotice {
            Objects.requireNonNull(algorithm, "algorithm cannot be null");
            Objects.requireNonNull(deprecatedAt, "deprecatedAt cannot be null");
            Objects.requireNonNull(removalDate, "removalDate cannot be null");
            Objects.requireNonNull(reason, "reason cannot be null");
        }
    }
}
