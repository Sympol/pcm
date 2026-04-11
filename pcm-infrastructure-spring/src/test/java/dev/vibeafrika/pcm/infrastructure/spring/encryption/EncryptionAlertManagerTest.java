package dev.vibeafrika.pcm.infrastructure.spring.encryption;

import dev.vibeafrika.pcm.infrastructure.encryption.EncryptionAlertManager;
import dev.vibeafrika.pcm.infrastructure.encryption.EncryptionAlertManager.Alert;
import dev.vibeafrika.pcm.infrastructure.encryption.EncryptionAlertManager.AlertSink;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link EncryptionAlertManager}.
 */
class EncryptionAlertManagerTest {

    private CapturingAlertSink sink;
    private EncryptionAlertManager manager;

    @BeforeEach
    void setUp() {
        sink    = new CapturingAlertSink();
        manager = new EncryptionAlertManager(sink);
    }

    // ── Encryption coverage ──────────────────────────────────────────────────

    @Test
    void checkEncryptionCoverage_belowThreshold_firesAlert() {
        manager.checkEncryptionCoverage(0.94);

        assertEquals(1, sink.alerts.size());
        assertEquals(EncryptionAlertManager.ALERT_ENCRYPTION_COVERAGE_LOW,
                sink.alerts.get(0).alertType());
    }

    @Test
    void checkEncryptionCoverage_atThreshold_doesNotFireAlert() {
        manager.checkEncryptionCoverage(0.95);
        assertTrue(sink.alerts.isEmpty());
    }

    @Test
    void checkEncryptionCoverage_aboveThreshold_doesNotFireAlert() {
        manager.checkEncryptionCoverage(1.0);
        assertTrue(sink.alerts.isEmpty());
    }

    // ── Key rotation compliance ──────────────────────────────────────────────

    @Test
    void checkKeyRotationCompliance_overdueMoreThan7Days_firesAlert() {
        Instant scheduled = Instant.now().minusSeconds(8 * 24 * 3600); // 8 days ago
        manager.checkKeyRotationCompliance(scheduled.minusSeconds(3600), scheduled);

        assertEquals(1, sink.alerts.size());
        assertEquals(EncryptionAlertManager.ALERT_KEY_ROTATION_OVERDUE,
                sink.alerts.get(0).alertType());
    }

    @Test
    void checkKeyRotationCompliance_overdueExactly7Days_doesNotFireAlert() {
        // Exactly 7 days overdue → NOT > 7, so no alert
        Instant scheduled = Instant.now().minusSeconds(7 * 24 * 3600);
        manager.checkKeyRotationCompliance(scheduled.minusSeconds(3600), scheduled);

        assertTrue(sink.alerts.isEmpty());
    }

    @Test
    void checkKeyRotationCompliance_notOverdue_doesNotFireAlert() {
        Instant scheduled = Instant.now().plusSeconds(3600); // in the future
        manager.checkKeyRotationCompliance(Instant.now().minusSeconds(3600), scheduled);

        assertTrue(sink.alerts.isEmpty());
    }

    // ── Failed decryption rate ───────────────────────────────────────────────

    @Test
    void checkFailedDecryptionRate_firesAfter5ConsecutiveMinutesAboveThreshold() {
        for (int i = 0; i < 4; i++) {
            manager.checkFailedDecryptionRate(11); // above threshold, but < 5 consecutive
            assertTrue(sink.alerts.isEmpty(), "Should not fire before 5 consecutive minutes");
        }
        manager.checkFailedDecryptionRate(11); // 5th consecutive minute
        assertEquals(1, sink.alerts.size());
        assertEquals(EncryptionAlertManager.ALERT_FAILED_DECRYPTION_RATE_HIGH,
                sink.alerts.get(0).alertType());
    }

    @Test
    void checkFailedDecryptionRate_resetsConsecutiveCountWhenRateDrops() {
        // 3 minutes above threshold
        for (int i = 0; i < 3; i++) {
            manager.checkFailedDecryptionRate(11);
        }
        // Rate drops
        manager.checkFailedDecryptionRate(5);
        assertTrue(sink.alerts.isEmpty(), "Alert should not fire after reset");

        // 4 more minutes above threshold (total < 5 from reset)
        for (int i = 0; i < 4; i++) {
            manager.checkFailedDecryptionRate(11);
        }
        assertTrue(sink.alerts.isEmpty(), "Alert should not fire – counter was reset");
    }

    // ── Immediate alerts ─────────────────────────────────────────────────────

    @Test
    void fireAlert_alwaysFiresImmediately() {
        manager.fireAlert(EncryptionAlertManager.ALERT_TAMPERING_DETECTED, "Auth tag mismatch");

        assertEquals(1, sink.alerts.size());
        assertEquals(EncryptionAlertManager.ALERT_TAMPERING_DETECTED,
                sink.alerts.get(0).alertType());
        assertEquals("Auth tag mismatch", sink.alerts.get(0).message());
    }

    @Test
    void fireAlert_kmsUnavailable_firesImmediately() {
        manager.fireAlert(EncryptionAlertManager.ALERT_KMS_UNAVAILABLE, "KMS health check failed");

        assertEquals(1, sink.alerts.size());
        assertEquals(EncryptionAlertManager.ALERT_KMS_UNAVAILABLE,
                sink.alerts.get(0).alertType());
    }

    // ── Counter overflow ─────────────────────────────────────────────────────

    @Test
    void checkCounterOverflow_aboveThreshold_firesAlert() {
        long count = EncryptionAlertManager.COUNTER_OVERFLOW_THRESHOLD + 1;
        manager.checkCounterOverflow(count);

        assertEquals(1, sink.alerts.size());
        assertEquals(EncryptionAlertManager.ALERT_COUNTER_OVERFLOW_IMMINENT,
                sink.alerts.get(0).alertType());
    }

    @Test
    void checkCounterOverflow_atThreshold_doesNotFireAlert() {
        manager.checkCounterOverflow(EncryptionAlertManager.COUNTER_OVERFLOW_THRESHOLD);
        assertTrue(sink.alerts.isEmpty());
    }

    @Test
    void checkCounterOverflow_belowThreshold_doesNotFireAlert() {
        manager.checkCounterOverflow(1_000L);
        assertTrue(sink.alerts.isEmpty());
    }

    // ── Performance latency ──────────────────────────────────────────────────

    @Test
    void checkPerformanceLatency_firesAfter5ConsecutiveChecksAboveThreshold() {
        long highLatency = EncryptionAlertManager.PERFORMANCE_P95_THRESHOLD_NS + 1;

        for (int i = 0; i < 4; i++) {
            manager.checkPerformanceLatency(highLatency);
            assertTrue(sink.alerts.isEmpty(), "Should not fire before 5 consecutive checks");
        }
        manager.checkPerformanceLatency(highLatency); // 5th check
        assertEquals(1, sink.alerts.size());
        assertEquals(EncryptionAlertManager.ALERT_PERFORMANCE_DEGRADED,
                sink.alerts.get(0).alertType());
    }

    @Test
    void checkPerformanceLatency_resetsConsecutiveCountWhenLatencyDrops() {
        long highLatency = EncryptionAlertManager.PERFORMANCE_P95_THRESHOLD_NS + 1;
        long lowLatency  = EncryptionAlertManager.PERFORMANCE_P95_THRESHOLD_NS - 1;

        for (int i = 0; i < 3; i++) {
            manager.checkPerformanceLatency(highLatency);
        }
        manager.checkPerformanceLatency(lowLatency); // drops below threshold → reset
        assertTrue(sink.alerts.isEmpty());

        for (int i = 0; i < 4; i++) {
            manager.checkPerformanceLatency(highLatency);
        }
        assertTrue(sink.alerts.isEmpty(), "Alert should not fire – counter was reset");
    }

    // ── Alert sink integration ───────────────────────────────────────────────

    @Test
    void alertSink_receivesAlertWhenRegistered() {
        manager.fireAlert("CUSTOM_ALERT", "test message");

        assertEquals(1, sink.alerts.size());
        Alert alert = sink.alerts.get(0);
        assertEquals("CUSTOM_ALERT", alert.alertType());
        assertEquals("test message", alert.message());
        assertNotNull(alert.timestamp());
        assertNotNull(alert.metadata());
    }

    @Test
    void noAlertSink_doesNotThrow() {
        EncryptionAlertManager noSinkManager = new EncryptionAlertManager();
        assertDoesNotThrow(() -> noSinkManager.fireAlert("TEST", "no sink configured"));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    static class CapturingAlertSink implements AlertSink {
        final List<Alert> alerts = new ArrayList<>();

        @Override
        public void sendAlert(Alert alert) {
            alerts.add(alert);
        }
    }
}
