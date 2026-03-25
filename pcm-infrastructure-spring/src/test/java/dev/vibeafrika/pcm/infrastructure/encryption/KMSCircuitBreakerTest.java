package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link KMSCircuitBreaker}.
 */
@ExtendWith(MockitoExtension.class)
class KMSCircuitBreakerTest {

    @Mock
    private IKMSClient primaryKms;

    @Mock
    private IKMSClient secondaryKms;

    private KMSCircuitBreaker circuitBreaker;

    private static final UUID KEK_ID = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        circuitBreaker = new KMSCircuitBreaker(primaryKms);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Initial state
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Validates: circuit breaker pattern is implemented.
     */
    @Test
    void circuitBreaker_initialState_isClosed() {
        assertThat(circuitBreaker.getState())
                .isEqualTo(KMSCircuitBreaker.CircuitBreakerState.CLOSED);
        assertThat(circuitBreaker.isReadOnly()).isFalse();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CLOSED → OPEN transition
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Validates: health check failure opens the circuit.
     */
    @Test
    void circuitBreaker_healthCheckFails_transitionsToOpen() {
        when(primaryKms.healthCheck())
                .thenReturn(Result.failure(KMSError.of("KMS_UNAVAILABLE", "KMS is down")));

        circuitBreaker.healthCheck();

        assertThat(circuitBreaker.getState())
                .isEqualTo(KMSCircuitBreaker.CircuitBreakerState.OPEN);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OPEN state behaviour
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Validates: encryption is rejected when circuit is OPEN.
     */
    @Test
    void circuitBreaker_openState_rejectsEncryptDEK() {
        openCircuit();

        DEK dek = DEK.of(new byte[32]);
        Result<EncryptedDEK, KMSError> result = circuitBreaker.encryptDEK(dek, KEK_ID);

        assertThat(result.isFailure()).isTrue();
        assertThat(result.getError().orElseThrow().getCode()).isEqualTo("KMS_UNAVAILABLE");
        // Primary KMS should NOT have been called
        verify(primaryKms, never()).encryptDEK(any(), any());
    }

    /**
     * Validates: decryption is allowed when circuit is OPEN (read-only mode).
     */
    @Test
    void circuitBreaker_openState_allowsDecryptDEK() {
        openCircuit();

        EncryptedDEK encryptedDEK = EncryptedDEK.of(new byte[48], KEK_ID);
        DEK plainDEK = DEK.of(new byte[32]);
        when(primaryKms.decryptDEK(any(), any())).thenReturn(Result.success(plainDEK));

        Result<DEK, KMSError> result = circuitBreaker.decryptDEK(encryptedDEK, KEK_ID);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getValue().orElseThrow()).isEqualTo(plainDEK);
    }

    /**
     * Validates: generateKEK is rejected when circuit is OPEN.
     */
    @Test
    void circuitBreaker_openState_rejectsGenerateKEK() {
        openCircuit();

        Result<UUID, KMSError> result = circuitBreaker.generateKEK(BoundedContext.PROFILE, Environment.PROD);

        assertThat(result.isFailure()).isTrue();
        assertThat(result.getError().orElseThrow().getCode()).isEqualTo("KMS_UNAVAILABLE");
        verify(primaryKms, never()).generateKEK(any(), any());
    }

    /**
     * Validates: isReadOnly() is true when OPEN with no secondary.
     */
    @Test
    void circuitBreaker_openState_noSecondary_isReadOnly() {
        openCircuit();

        assertThat(circuitBreaker.isReadOnly()).isTrue();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Failover to secondary KMS
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Validates: failover to secondary KMS on primary failure.
     */
    @Test
    void circuitBreaker_withSecondaryKms_failsOverOnPrimaryFailure() {
        circuitBreaker = new KMSCircuitBreaker(primaryKms, secondaryKms);

        // Primary health check fails
        when(primaryKms.healthCheck())
                .thenReturn(Result.failure(KMSError.of("KMS_UNAVAILABLE", "Primary down")));
        // Secondary health check succeeds
        when(secondaryKms.healthCheck())
                .thenReturn(Result.success(KMSHealth.healthy(5L)));

        circuitBreaker.healthCheck();

        // Circuit should remain CLOSED (using secondary)
        assertThat(circuitBreaker.getState())
                .isEqualTo(KMSCircuitBreaker.CircuitBreakerState.CLOSED);
        assertThat(circuitBreaker.isReadOnly()).isFalse();

        // Subsequent calls should go to secondary
        DEK dek = DEK.of(new byte[32]);
        EncryptedDEK encDEK = EncryptedDEK.of(new byte[48], KEK_ID);
        when(secondaryKms.encryptDEK(any(), any())).thenReturn(Result.success(encDEK));

        Result<EncryptedDEK, KMSError> encResult = circuitBreaker.encryptDEK(dek, KEK_ID);
        assertThat(encResult.isSuccess()).isTrue();
        verify(secondaryKms).encryptDEK(any(), any());
        verify(primaryKms, never()).encryptDEK(any(), any());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HALF_OPEN transitions
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Validates: successful probe in HALF_OPEN transitions to CLOSED.
     */
    @Test
    void circuitBreaker_halfOpen_successfulCall_transitionsToClosed() throws Exception {
        openCircuit();

        // Force transition to HALF_OPEN by manipulating the openedAt timestamp
        forceHalfOpen();

        assertThat(circuitBreaker.getState())
                .isEqualTo(KMSCircuitBreaker.CircuitBreakerState.HALF_OPEN);

        // Successful encryptDEK probe
        EncryptedDEK encDEK = EncryptedDEK.of(new byte[48], KEK_ID);
        when(primaryKms.encryptDEK(any(), any())).thenReturn(Result.success(encDEK));

        DEK dek = DEK.of(new byte[32]);
        Result<EncryptedDEK, KMSError> result = circuitBreaker.encryptDEK(dek, KEK_ID);

        assertThat(result.isSuccess()).isTrue();
        assertThat(circuitBreaker.getState())
                .isEqualTo(KMSCircuitBreaker.CircuitBreakerState.CLOSED);
    }

    /**
     * Validates: failed probe in HALF_OPEN transitions back to OPEN.
     */
    @Test
    void circuitBreaker_halfOpen_failedCall_transitionsToOpen() throws Exception {
        openCircuit();
        forceHalfOpen();

        assertThat(circuitBreaker.getState())
                .isEqualTo(KMSCircuitBreaker.CircuitBreakerState.HALF_OPEN);

        // Failing encryptDEK probe
        when(primaryKms.encryptDEK(any(), any()))
                .thenReturn(Result.failure(KMSError.of("KMS_UNAVAILABLE", "Still down")));

        DEK dek = DEK.of(new byte[32]);
        Result<EncryptedDEK, KMSError> result = circuitBreaker.encryptDEK(dek, KEK_ID);

        assertThat(result.isFailure()).isTrue();
        assertThat(circuitBreaker.getState())
                .isEqualTo(KMSCircuitBreaker.CircuitBreakerState.OPEN);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Recovery
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Validates: normal operations resume within 60 seconds of KMS recovery.
     * Uses the HALF_OPEN → CLOSED path triggered by a successful health check.
     */
    @Test
    void circuitBreaker_kmsRecovery_resumesNormalOperations() throws Exception {
        openCircuit();
        forceHalfOpen();

        // Health check now succeeds (KMS recovered)
        when(primaryKms.healthCheck()).thenReturn(Result.success(KMSHealth.healthy(3L)));

        circuitBreaker.healthCheck();

        assertThat(circuitBreaker.getState())
                .isEqualTo(KMSCircuitBreaker.CircuitBreakerState.CLOSED);
        assertThat(circuitBreaker.isReadOnly()).isFalse();

        // Encryption should now be allowed
        EncryptedDEK encDEK = EncryptedDEK.of(new byte[48], KEK_ID);
        when(primaryKms.encryptDEK(any(), any())).thenReturn(Result.success(encDEK));

        DEK dek = DEK.of(new byte[32]);
        Result<EncryptedDEK, KMSError> result = circuitBreaker.encryptDEK(dek, KEK_ID);
        assertThat(result.isSuccess()).isTrue();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /** Opens the circuit by simulating a health check failure. */
    private void openCircuit() {
        when(primaryKms.healthCheck())
                .thenReturn(Result.failure(KMSError.of("KMS_UNAVAILABLE", "KMS is down")));
        circuitBreaker.healthCheck();
        assertThat(circuitBreaker.getState())
                .isEqualTo(KMSCircuitBreaker.CircuitBreakerState.OPEN);
    }

    /**
     * Forces the circuit into HALF_OPEN by back-dating the openedAt timestamp
     * beyond the recovery timeout using reflection, then triggering evaluateState
     * via a no-op call that reads the state.
     */
    private void forceHalfOpen() throws Exception {
        // Back-date the openedAt timestamp so the recovery window has elapsed
        var field = KMSCircuitBreaker.class.getDeclaredField("openedAtMs");
        field.setAccessible(true);
        var atomicLong = (java.util.concurrent.atomic.AtomicLong) field.get(circuitBreaker);
        atomicLong.set(System.currentTimeMillis() - KMSCircuitBreaker.RECOVERY_TIMEOUT_MS - 1_000L);

        // evaluateState() is called inside encryptDEK/generateKEK/decryptDEK/healthCheck.
        // We trigger it by calling decryptDEK (which always passes through and calls evaluateState).
        // We need a stub that won't interfere with later test assertions.
        EncryptedDEK dummy = EncryptedDEK.of(new byte[48], KEK_ID);
        lenient().when(primaryKms.decryptDEK(any(), any()))
                .thenReturn(Result.success(DEK.of(new byte[32])));
        circuitBreaker.decryptDEK(dummy, KEK_ID);
        // After this call evaluateState() will have transitioned OPEN → HALF_OPEN
    }
}
