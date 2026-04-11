package dev.vibeafrika.pcm.infrastructure.encryption;

import io.micrometer.core.instrument.*;

import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Micrometer-based metrics for the PII encryption subsystem.
 *
 * <p>All metric names use the {@code pcm.encryption.} prefix.
 * This class is plain Java (no Spring annotations) so it can be used in tests
 * without a Spring context.
 */
public class EncryptionMetrics {

    // ── Metric name constants ────────────────────────────────────────────────
    public static final String METRIC_ENCRYPTION_COVERAGE      = "pcm.encryption.coverage";
    public static final String METRIC_KEY_ROTATION_COMPLIANCE  = "pcm.encryption.key.rotation.compliance";
    public static final String METRIC_FAILED_DECRYPTIONS       = "pcm.encryption.decryption.failures";
    public static final String METRIC_KMS_AVAILABILITY         = "pcm.encryption.kms.availability";
    public static final String METRIC_ENCRYPT_LATENCY          = "pcm.encryption.latency";
    public static final String METRIC_DECRYPT_LATENCY          = "pcm.decryption.latency";
    public static final String METRIC_DEK_CACHE_HITS           = "pcm.encryption.dek.cache.hits";
    public static final String METRIC_DEK_CACHE_MISSES         = "pcm.encryption.dek.cache.misses";
    public static final String METRIC_KMS_MTTR                 = "pcm.encryption.kms.mttr.seconds";

    // ── Internal state ───────────────────────────────────────────────────────
    private final AtomicReference<Double> encryptionCoverage     = new AtomicReference<>(1.0);
    private final AtomicReference<Double> keyRotationCompliance  = new AtomicReference<>(1.0);
    private final AtomicReference<Double> kmsAvailability        = new AtomicReference<>(1.0);

    /** Epoch-second when KMS first became unavailable; 0 = currently available. */
    private final AtomicLong kmsUnavailableSince = new AtomicLong(0L);

    private final Counter failedDecryptionsCounter;
    private final Timer   encryptLatencyTimer;
    private final Timer   decryptLatencyTimer;
    private final Counter cacheHitsCounter;
    private final Counter cacheMissesCounter;

    // ── Constructor ──────────────────────────────────────────────────────────

    public EncryptionMetrics(MeterRegistry registry) {

        // Gauges backed by AtomicReference<Double>
        Gauge.builder(METRIC_ENCRYPTION_COVERAGE, encryptionCoverage, AtomicReference::get)
                .description("Ratio of encrypted fields to total fields (0.0–1.0)")
                .register(registry);

        Gauge.builder(METRIC_KEY_ROTATION_COMPLIANCE, keyRotationCompliance, AtomicReference::get)
                .description("Ratio of keys compliant with rotation policy (0.0–1.0)")
                .register(registry);

        Gauge.builder(METRIC_KMS_AVAILABILITY, kmsAvailability, AtomicReference::get)
                .description("KMS availability: 1.0 = available, 0.0 = unavailable")
                .register(registry);

        Gauge.builder(METRIC_KMS_MTTR, kmsUnavailableSince, since -> {
            long s = since.get();
            if (s == 0L) return 0.0;
            return (double) (Instant.now().getEpochSecond() - s);
        })
                .description("Seconds KMS has been continuously unavailable (MTTR tracking)")
                .register(registry);

        // Counter for failed decryptions
        failedDecryptionsCounter = Counter.builder(METRIC_FAILED_DECRYPTIONS)
                .description("Total number of failed decryption operations")
                .register(registry);

        // Timers with p50 / p95 / p99 percentiles
        encryptLatencyTimer = Timer.builder(METRIC_ENCRYPT_LATENCY)
                .description("Encryption operation latency")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(registry);

        decryptLatencyTimer = Timer.builder(METRIC_DECRYPT_LATENCY)
                .description("Decryption operation latency")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(registry);

        // DEK cache hit / miss counters
        cacheHitsCounter = Counter.builder(METRIC_DEK_CACHE_HITS)
                .description("Number of DEK cache hits")
                .register(registry);

        cacheMissesCounter = Counter.builder(METRIC_DEK_CACHE_MISSES)
                .description("Number of DEK cache misses")
                .register(registry);
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /** Records a single encrypt operation latency in nanoseconds. */
    public void recordEncryptLatency(long nanos) {
        encryptLatencyTimer.record(nanos, TimeUnit.NANOSECONDS);
    }

    /** Records a single decrypt operation latency in nanoseconds. */
    public void recordDecryptLatency(long nanos) {
        decryptLatencyTimer.record(nanos, TimeUnit.NANOSECONDS);
    }

    /** Increments the failed-decryption counter by one. */
    public void incrementFailedDecryptions() {
        failedDecryptionsCounter.increment();
    }

    /** Records a DEK cache hit. */
    public void recordCacheHit() {
        cacheHitsCounter.increment();
    }

    /** Records a DEK cache miss. */
    public void recordCacheMiss() {
        cacheMissesCounter.increment();
    }

    /**
     * Updates the encryption coverage gauge.
     *
     * @param ratio value between 0.0 (no fields encrypted) and 1.0 (all fields encrypted)
     */
    public void updateEncryptionCoverage(double ratio) {
        encryptionCoverage.set(ratio);
    }

    /**
     * Updates the key-rotation compliance gauge.
     *
     * @param ratio value between 0.0 and 1.0
     */
    public void updateKeyRotationCompliance(double ratio) {
        keyRotationCompliance.set(ratio);
    }

    /**
     * Updates KMS availability and MTTR tracking.
     *
     * @param available {@code true} if KMS is reachable, {@code false} otherwise
     */
    public void updateKmsAvailability(boolean available) {
        if (available) {
            kmsAvailability.set(1.0);
            kmsUnavailableSince.set(0L);
        } else {
            kmsAvailability.set(0.0);
            // Record the first moment KMS became unavailable (CAS: only set if currently 0)
            kmsUnavailableSince.compareAndSet(0L, Instant.now().getEpochSecond());
        }
    }

    /**
     * Returns the DEK cache hit rate as a value between 0.0 and 1.0.
     * Returns 1.0 when no cache operations have been recorded yet.
     */
    public double getCacheHitRate() {
        double hits   = cacheHitsCounter.count();
        double misses = cacheMissesCounter.count();
        double total  = hits + misses;
        if (total == 0.0) return 1.0;
        return hits / total;
    }
}
