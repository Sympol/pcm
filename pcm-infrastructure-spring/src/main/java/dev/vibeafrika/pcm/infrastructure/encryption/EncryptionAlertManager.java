package dev.vibeafrika.pcm.infrastructure.encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Evaluates alert conditions for the PII encryption subsystem and fires alerts
 * via SLF4J (ERROR level) and an optional pluggable {@link AlertSink}.
 *
 * <p>This class is plain Java (no Spring annotations) so it can be used in tests
 * without a Spring context.
 */
public class EncryptionAlertManager {

    private static final Logger log = LoggerFactory.getLogger(EncryptionAlertManager.class);

    // ── Alert type constants ─────────────────────────────────────────────────
    public static final String ALERT_ENCRYPTION_COVERAGE_LOW      = "ENCRYPTION_COVERAGE_LOW";
    public static final String ALERT_KEY_ROTATION_OVERDUE         = "KEY_ROTATION_OVERDUE";
    public static final String ALERT_FAILED_DECRYPTION_RATE_HIGH  = "FAILED_DECRYPTION_RATE_HIGH";
    public static final String ALERT_TAMPERING_DETECTED           = "TAMPERING_DETECTED";
    public static final String ALERT_KMS_UNAVAILABLE              = "KMS_UNAVAILABLE";
    public static final String ALERT_KEY_COMPROMISE_SUSPECTED     = "KEY_COMPROMISE_SUSPECTED";
    public static final String ALERT_ENVIRONMENT_MISMATCH         = "ENVIRONMENT_MISMATCH";
    public static final String ALERT_COUNTER_OVERFLOW_IMMINENT    = "COUNTER_OVERFLOW_IMMINENT";
    public static final String ALERT_PERFORMANCE_DEGRADED         = "PERFORMANCE_DEGRADED";

    // ── Threshold constants ──────────────────────────────────────────────────
    public static final double COVERAGE_THRESHOLD                 = 0.95;
    public static final long   KEY_ROTATION_OVERDUE_DAYS          = 7L;
    public static final int    FAILED_DECRYPTION_RATE_THRESHOLD   = 10;   // per minute
    public static final int    FAILED_DECRYPTION_CONSECUTIVE_MINUTES = 5;
    public static final long   COUNTER_OVERFLOW_THRESHOLD         = (long) Math.pow(2, 31);
    public static final long   PERFORMANCE_P95_THRESHOLD_NS       = 50_000_000L; // 50 ms
    public static final int    PERFORMANCE_CONSECUTIVE_THRESHOLD  = 5;

    // ── Internal state ───────────────────────────────────────────────────────
    private final AtomicInteger consecutiveHighDecryptionMinutes = new AtomicInteger(0);
    private final AtomicInteger consecutiveHighLatencyChecks     = new AtomicInteger(0);

    private final AlertSink alertSink; // nullable

    // ── Constructor ──────────────────────────────────────────────────────────

    /** Creates an alert manager with no external sink (log-only). */
    public EncryptionAlertManager() {
        this(null);
    }

    /** Creates an alert manager with an optional external sink. */
    public EncryptionAlertManager(AlertSink alertSink) {
        this.alertSink = alertSink;
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /**
     * Checks whether encryption coverage has dropped below the 95 % threshold.
     *
     * @param coverageRatio current ratio of encrypted fields (0.0–1.0)
     */
    public void checkEncryptionCoverage(double coverageRatio) {
        if (coverageRatio < COVERAGE_THRESHOLD) {
            Map<String, Object> meta = new HashMap<>();
            meta.put("coverageRatio", coverageRatio);
            meta.put("threshold", COVERAGE_THRESHOLD);
            dispatch(ALERT_ENCRYPTION_COVERAGE_LOW,
                    String.format("Encryption coverage %.2f%% is below threshold %.0f%%",
                            coverageRatio * 100, COVERAGE_THRESHOLD * 100),
                    meta);
        }
    }

    /**
     * Checks whether a key rotation is overdue by more than 7 days.
     *
     * @param lastRotation      when the key was last rotated
     * @param scheduledRotation when the next rotation was scheduled
     */
    public void checkKeyRotationCompliance(Instant lastRotation, Instant scheduledRotation) {
        if (scheduledRotation == null) return;
        long overdueDays = ChronoUnit.DAYS.between(scheduledRotation, Instant.now());
        if (overdueDays > KEY_ROTATION_OVERDUE_DAYS) {
            Map<String, Object> meta = new HashMap<>();
            meta.put("lastRotation", lastRotation != null ? lastRotation.toString() : "unknown");
            meta.put("scheduledRotation", scheduledRotation.toString());
            meta.put("overdueDays", overdueDays);
            dispatch(ALERT_KEY_ROTATION_OVERDUE,
                    String.format("Key rotation is %d days overdue (threshold %d days)",
                            overdueDays, KEY_ROTATION_OVERDUE_DAYS),
                    meta);
        }
    }

    /**
     * Checks whether the failed-decryption rate exceeds the threshold for 5
     * consecutive minutes.  Resets the consecutive counter when the rate drops.
     *
     * @param failuresLastMinute number of failed decryptions in the last minute
     */
    public void checkFailedDecryptionRate(int failuresLastMinute) {
        if (failuresLastMinute > FAILED_DECRYPTION_RATE_THRESHOLD) {
            int consecutive = consecutiveHighDecryptionMinutes.incrementAndGet();
            if (consecutive >= FAILED_DECRYPTION_CONSECUTIVE_MINUTES) {
                Map<String, Object> meta = new HashMap<>();
                meta.put("failuresLastMinute", failuresLastMinute);
                meta.put("consecutiveMinutes", consecutive);
                meta.put("threshold", FAILED_DECRYPTION_RATE_THRESHOLD);
                dispatch(ALERT_FAILED_DECRYPTION_RATE_HIGH,
                        String.format("Failed decryption rate %d/min exceeded threshold %d/min for %d consecutive minutes",
                                failuresLastMinute, FAILED_DECRYPTION_RATE_THRESHOLD, consecutive),
                        meta);
            }
        } else {
            consecutiveHighDecryptionMinutes.set(0);
        }
    }

    /**
     * Fires an alert immediately (e.g. tampering, KMS unavailable, key compromise,
     * environment mismatch).
     *
     * @param alertType the alert type identifier
     * @param message   human-readable description
     */
    public void fireAlert(String alertType, String message) {
        dispatch(alertType, message, new HashMap<>());
    }

    /**
     * Checks whether the IV counter is approaching overflow (> 2^31 operations).
     *
     * @param currentCount current operation count for the key
     */
    public void checkCounterOverflow(long currentCount) {
        if (currentCount > COUNTER_OVERFLOW_THRESHOLD) {
            Map<String, Object> meta = new HashMap<>();
            meta.put("currentCount", currentCount);
            meta.put("threshold", COUNTER_OVERFLOW_THRESHOLD);
            dispatch(ALERT_COUNTER_OVERFLOW_IMMINENT,
                    String.format("IV counter %d exceeds overflow threshold %d – DEK rotation required",
                            currentCount, COUNTER_OVERFLOW_THRESHOLD),
                    meta);
        }
    }

    /**
     * Checks whether p95 encryption latency exceeds 50 ms for 5 consecutive checks.
     * Resets the consecutive counter when latency drops below the threshold.
     *
     * @param p95Nanos p95 latency in nanoseconds
     */
    public void checkPerformanceLatency(long p95Nanos) {
        if (p95Nanos > PERFORMANCE_P95_THRESHOLD_NS) {
            int consecutive = consecutiveHighLatencyChecks.incrementAndGet();
            if (consecutive >= PERFORMANCE_CONSECUTIVE_THRESHOLD) {
                Map<String, Object> meta = new HashMap<>();
                meta.put("p95Nanos", p95Nanos);
                meta.put("p95Ms", p95Nanos / 1_000_000.0);
                meta.put("thresholdMs", PERFORMANCE_P95_THRESHOLD_NS / 1_000_000.0);
                meta.put("consecutiveChecks", consecutive);
                dispatch(ALERT_PERFORMANCE_DEGRADED,
                        String.format("p95 encryption latency %.1f ms exceeds threshold %.0f ms for %d consecutive checks",
                                p95Nanos / 1_000_000.0,
                                PERFORMANCE_P95_THRESHOLD_NS / 1_000_000.0,
                                consecutive),
                        meta);
            }
        } else {
            consecutiveHighLatencyChecks.set(0);
        }
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    private void dispatch(String alertType, String message, Map<String, Object> metadata) {
        Alert alert = new Alert(alertType, message, Instant.now(), metadata);

        // Always log at ERROR level with structured fields
        log.error("[ENCRYPTION ALERT] type={} message=\"{}\" metadata={}",
                alertType, message, metadata);

        // Optionally forward to the pluggable sink
        if (alertSink != null) {
            alertSink.sendAlert(alert);
        }
    }

    // ── Nested types ─────────────────────────────────────────────────────────

    /** Pluggable sink for receiving alerts (e.g. PagerDuty, Slack, SNS). */
    public interface AlertSink {
        void sendAlert(Alert alert);
    }

    /** Immutable alert payload. */
    public record Alert(
            String alertType,
            String message,
            Instant timestamp,
            Map<String, Object> metadata
    ) {}
}
