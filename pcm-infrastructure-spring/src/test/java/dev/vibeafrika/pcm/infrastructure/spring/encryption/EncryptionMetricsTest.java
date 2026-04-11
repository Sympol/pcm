package dev.vibeafrika.pcm.infrastructure.spring.encryption;

import dev.vibeafrika.pcm.infrastructure.encryption.EncryptionMetrics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link EncryptionMetrics}.
 */
class EncryptionMetricsTest {

    private SimpleMeterRegistry registry;
    private EncryptionMetrics metrics;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        metrics  = new EncryptionMetrics(registry);
    }

    // ── Registration ─────────────────────────────────────────────────────────

    @Test
    void allMetricsAreRegisteredOnConstruction() {
        assertNotNull(registry.find(EncryptionMetrics.METRIC_ENCRYPTION_COVERAGE).gauge(),
                "encryption coverage gauge should be registered");
        assertNotNull(registry.find(EncryptionMetrics.METRIC_KEY_ROTATION_COMPLIANCE).gauge(),
                "key rotation compliance gauge should be registered");
        assertNotNull(registry.find(EncryptionMetrics.METRIC_KMS_AVAILABILITY).gauge(),
                "KMS availability gauge should be registered");
        assertNotNull(registry.find(EncryptionMetrics.METRIC_KMS_MTTR).gauge(),
                "KMS MTTR gauge should be registered");
        assertNotNull(registry.find(EncryptionMetrics.METRIC_FAILED_DECRYPTIONS).counter(),
                "failed decryptions counter should be registered");
        assertNotNull(registry.find(EncryptionMetrics.METRIC_ENCRYPT_LATENCY).timer(),
                "encrypt latency timer should be registered");
        assertNotNull(registry.find(EncryptionMetrics.METRIC_DECRYPT_LATENCY).timer(),
                "decrypt latency timer should be registered");
        assertNotNull(registry.find(EncryptionMetrics.METRIC_DEK_CACHE_HITS).counter(),
                "DEK cache hits counter should be registered");
        assertNotNull(registry.find(EncryptionMetrics.METRIC_DEK_CACHE_MISSES).counter(),
                "DEK cache misses counter should be registered");
    }

    // ── Latency timers ───────────────────────────────────────────────────────

    @Test
    void recordEncryptLatency_updatesTimer() {
        metrics.recordEncryptLatency(1_000_000L); // 1 ms
        metrics.recordEncryptLatency(2_000_000L); // 2 ms

        Timer timer = registry.find(EncryptionMetrics.METRIC_ENCRYPT_LATENCY).timer();
        assertNotNull(timer);
        assertEquals(2, timer.count());
    }

    @Test
    void recordDecryptLatency_updatesTimer() {
        metrics.recordDecryptLatency(500_000L); // 0.5 ms

        Timer timer = registry.find(EncryptionMetrics.METRIC_DECRYPT_LATENCY).timer();
        assertNotNull(timer);
        assertEquals(1, timer.count());
    }

    // ── Failed decryptions counter ───────────────────────────────────────────

    @Test
    void incrementFailedDecryptions_incrementsCounter() {
        metrics.incrementFailedDecryptions();
        metrics.incrementFailedDecryptions();

        Counter counter = registry.find(EncryptionMetrics.METRIC_FAILED_DECRYPTIONS).counter();
        assertNotNull(counter);
        assertEquals(2.0, counter.count(), 0.001);
    }

    // ── DEK cache counters ───────────────────────────────────────────────────

    @Test
    void recordCacheHit_incrementsHitCounter() {
        metrics.recordCacheHit();
        metrics.recordCacheHit();

        Counter hits = registry.find(EncryptionMetrics.METRIC_DEK_CACHE_HITS).counter();
        assertNotNull(hits);
        assertEquals(2.0, hits.count(), 0.001);
    }

    @Test
    void recordCacheMiss_incrementsMissCounter() {
        metrics.recordCacheMiss();

        Counter misses = registry.find(EncryptionMetrics.METRIC_DEK_CACHE_MISSES).counter();
        assertNotNull(misses);
        assertEquals(1.0, misses.count(), 0.001);
    }

    // ── Cache hit rate ───────────────────────────────────────────────────────

    @Test
    void getCacheHitRate_returnsOneWhenNoOperations() {
        assertEquals(1.0, metrics.getCacheHitRate(), 0.001,
                "Hit rate should be 1.0 when no cache operations have occurred");
    }

    @Test
    void getCacheHitRate_returnsCorrectRatioAfterOperations() {
        metrics.recordCacheHit();
        metrics.recordCacheHit();
        metrics.recordCacheHit();
        metrics.recordCacheMiss();

        // 3 hits / 4 total = 0.75
        assertEquals(0.75, metrics.getCacheHitRate(), 0.001);
    }

    @Test
    void getCacheHitRate_returnsZeroWhenAllMisses() {
        metrics.recordCacheMiss();
        metrics.recordCacheMiss();

        assertEquals(0.0, metrics.getCacheHitRate(), 0.001);
    }

    // ── KMS availability & MTTR ──────────────────────────────────────────────

    @Test
    void updateKmsAvailability_false_setsGaugeToZeroAndStartsMttrTracking() throws InterruptedException {
        metrics.updateKmsAvailability(false);

        Gauge availGauge = registry.find(EncryptionMetrics.METRIC_KMS_AVAILABILITY).gauge();
        assertNotNull(availGauge);
        assertEquals(0.0, availGauge.value(), 0.001,
                "KMS availability gauge should be 0.0 when unavailable");

        // Give MTTR gauge a moment to reflect elapsed time
        Thread.sleep(10);
        Gauge mttrGauge = registry.find(EncryptionMetrics.METRIC_KMS_MTTR).gauge();
        assertNotNull(mttrGauge);
        assertTrue(mttrGauge.value() >= 0.0,
                "MTTR gauge should be non-negative when KMS is unavailable");
    }

    @Test
    void updateKmsAvailability_true_setsGaugeToOneAndResetsMttr() throws InterruptedException {
        // First mark unavailable
        metrics.updateKmsAvailability(false);
        Thread.sleep(10);

        // Then mark available again
        metrics.updateKmsAvailability(true);

        Gauge availGauge = registry.find(EncryptionMetrics.METRIC_KMS_AVAILABILITY).gauge();
        assertNotNull(availGauge);
        assertEquals(1.0, availGauge.value(), 0.001,
                "KMS availability gauge should be 1.0 when available");

        Gauge mttrGauge = registry.find(EncryptionMetrics.METRIC_KMS_MTTR).gauge();
        assertNotNull(mttrGauge);
        assertEquals(0.0, mttrGauge.value(), 0.001,
                "MTTR gauge should be reset to 0.0 when KMS becomes available again");
    }

    // ── Coverage / compliance gauges ─────────────────────────────────────────

    @Test
    void updateEncryptionCoverage_updatesGauge() {
        metrics.updateEncryptionCoverage(0.87);

        Gauge gauge = registry.find(EncryptionMetrics.METRIC_ENCRYPTION_COVERAGE).gauge();
        assertNotNull(gauge);
        assertEquals(0.87, gauge.value(), 0.001);
    }

    @Test
    void updateKeyRotationCompliance_updatesGauge() {
        metrics.updateKeyRotationCompliance(0.60);

        Gauge gauge = registry.find(EncryptionMetrics.METRIC_KEY_ROTATION_COMPLIANCE).gauge();
        assertNotNull(gauge);
        assertEquals(0.60, gauge.value(), 0.001);
    }
}
