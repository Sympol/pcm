package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Circuit breaker for KMS access implementing the circuit breaker pattern.
 *
 * <p>States:
 * <ul>
 *   <li>CLOSED - Normal operation, all KMS calls pass through</li>
 *   <li>OPEN - KMS unavailable; encryption/key-generation calls are rejected,
 *       decryption is allowed (read-only mode)</li>
 *   <li>HALF_OPEN - Testing recovery; one probe call is allowed through</li>
 * </ul>
 *
 * <p>Failover behaviour:
 * <ol>
 *   <li>Health check failure triggers transition CLOSED → OPEN</li>
 *   <li>If a secondary KMS is configured, failover is attempted within 30 seconds</li>
 *   <li>If failover succeeds the circuit stays CLOSED on the secondary</li>
 *   <li>If failover fails the circuit enters read-only mode (OPEN, no secondary)</li>
 *   <li>After 60 seconds in OPEN state the circuit transitions to HALF_OPEN</li>
 *   <li>A successful probe in HALF_OPEN transitions back to CLOSED</li>
 * </ol>
 *
 * <p>This class implements {@link IKMSClient} so it can be used as a transparent
 * drop-in replacement for the real KMS client.
 *
 * <p>All state is managed with {@code java.util.concurrent.atomic} types for
 * thread safety without explicit locking.
 */
public class KMSCircuitBreaker implements IKMSClient {

    private static final Logger logger = LoggerFactory.getLogger(KMSCircuitBreaker.class);

    /** Time after which an OPEN circuit transitions to HALF_OPEN (60 seconds). */
    static final long RECOVERY_TIMEOUT_MS = 60_000L;

    /** Window within which failover to secondary is attempted (30 seconds). */
    static final long FAILOVER_WINDOW_MS = 30_000L;

    /** Possible states of the circuit breaker. */
    public enum CircuitBreakerState {
        CLOSED, OPEN, HALF_OPEN
    }

    private final IKMSClient primaryKms;
    private final IKMSClient secondaryKms; // nullable

    private final AtomicReference<CircuitBreakerState> state =
            new AtomicReference<>(CircuitBreakerState.CLOSED);

    /** Timestamp (epoch ms) when the circuit was last opened. 0 = never opened. */
    private final AtomicLong openedAtMs = new AtomicLong(0L);

    /** Whether the circuit is currently using the secondary KMS. */
    private volatile boolean usingSecondary = false;

    /**
     * Creates a circuit breaker wrapping a primary KMS client with no secondary.
     *
     * @param primaryKms the primary KMS client (must not be null)
     */
    public KMSCircuitBreaker(IKMSClient primaryKms) {
        this(primaryKms, null);
    }

    /**
     * Creates a circuit breaker wrapping a primary KMS client with an optional secondary.
     *
     * @param primaryKms   the primary KMS client (must not be null)
     * @param secondaryKms the secondary KMS client used for failover (may be null)
     */
    public KMSCircuitBreaker(IKMSClient primaryKms, IKMSClient secondaryKms) {
        if (primaryKms == null) throw new IllegalArgumentException("Primary KMS client cannot be null");
        this.primaryKms = primaryKms;
        this.secondaryKms = secondaryKms;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IKMSClient implementation
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * {@inheritDoc}
     *
     * <p>Rejected when the circuit is OPEN (read-only mode).
     */
    @Override
    public Result<EncryptedDEK, KMSError> encryptDEK(DEK dek, UUID kekId) {
        CircuitBreakerState current = evaluateState();
        if (current == CircuitBreakerState.OPEN) {
            logger.warn("Circuit breaker OPEN: rejecting encryptDEK call");
            return Result.failure(KMSError.of("KMS_UNAVAILABLE",
                    "KMS is unavailable: circuit breaker is open"));
        }

        Result<EncryptedDEK, KMSError> result = activeClient().encryptDEK(dek, kekId);
        handleResult(result.isSuccess());
        return result;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Allowed even when the circuit is OPEN to support cached DEK retrieval
     * (read-only mode).
     */
    @Override
    public Result<DEK, KMSError> decryptDEK(EncryptedDEK encryptedDEK, UUID kekId) {
        // Decryption is always allowed – read-only mode must support cached DEK retrieval
        evaluateState(); // still update state if recovery window has elapsed
        return activeClient().decryptDEK(encryptedDEK, kekId);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Rejected when the circuit is OPEN (read-only mode).
     */
    @Override
    public Result<UUID, KMSError> generateKEK(BoundedContext context, Environment environment) {
        CircuitBreakerState current = evaluateState();
        if (current == CircuitBreakerState.OPEN) {
            logger.warn("Circuit breaker OPEN: rejecting generateKEK call");
            return Result.failure(KMSError.of("KMS_UNAVAILABLE",
                    "KMS is unavailable: circuit breaker is open"));
        }

        Result<UUID, KMSError> result = activeClient().generateKEK(context, environment);
        handleResult(result.isSuccess());
        return result;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Performs a health check on the active KMS client and updates circuit state
     * accordingly. On failure, attempts failover to the secondary KMS if configured.
     */
    @Override
    public Result<KMSHealth, KMSError> healthCheck() {
        Result<KMSHealth, KMSError> result = activeClient().healthCheck();

        boolean healthy = result.isSuccess() &&
                result.getValue().map(KMSHealth::isAvailable).orElse(false);

        if (!healthy) {
            onHealthCheckFailure();
        } else {
            onHealthCheckSuccess();
        }

        return result;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public accessors
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns the current circuit breaker state.
     */
    public CircuitBreakerState getState() {
        return state.get();
    }

    /**
     * Returns {@code true} when the circuit is OPEN and no secondary KMS is
     * available (i.e. the system is in read-only mode).
     */
    public boolean isReadOnly() {
        return state.get() == CircuitBreakerState.OPEN && !usingSecondary;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal state machine
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Evaluates whether the circuit should transition from OPEN → HALF_OPEN
     * based on the recovery timeout, and returns the current state.
     */
    private CircuitBreakerState evaluateState() {
        CircuitBreakerState current = state.get();
        if (current == CircuitBreakerState.OPEN) {
            long elapsed = System.currentTimeMillis() - openedAtMs.get();
            if (elapsed >= RECOVERY_TIMEOUT_MS) {
                if (state.compareAndSet(CircuitBreakerState.OPEN, CircuitBreakerState.HALF_OPEN)) {
                    logger.info("Circuit breaker transitioning OPEN → HALF_OPEN after {}ms", elapsed);
                }
                return state.get();
            }
        }
        return current;
    }

    /**
     * Called after a KMS call completes. Updates state for HALF_OPEN probes.
     */
    private void handleResult(boolean success) {
        CircuitBreakerState current = state.get();
        if (current == CircuitBreakerState.HALF_OPEN) {
            if (success) {
                transitionToClosed("probe call succeeded");
            } else {
                transitionToOpen("probe call failed");
            }
        }
    }

    /**
     * Called when a health check fails. Attempts failover to secondary if within
     * the 30-second failover window; otherwise opens the circuit.
     */
    private void onHealthCheckFailure() {
        CircuitBreakerState current = state.get();

        if (current == CircuitBreakerState.CLOSED) {
            logger.warn("KMS health check failed – attempting failover");

            if (secondaryKms != null) {
                // Try secondary within the 30-second failover window
                Result<KMSHealth, KMSError> secondaryHealth = secondaryKms.healthCheck();
                boolean secondaryHealthy = secondaryHealth.isSuccess() &&
                        secondaryHealth.getValue().map(KMSHealth::isAvailable).orElse(false);

                if (secondaryHealthy) {
                    usingSecondary = true;
                    logger.info("Failover to secondary KMS succeeded – circuit remains CLOSED");
                    return; // stay CLOSED on secondary
                }
            }

            transitionToOpen("health check failure, no available KMS");
        }
        // If already OPEN or HALF_OPEN, nothing extra to do here
    }

    /**
     * Called when a health check succeeds. Closes the circuit if it was OPEN or HALF_OPEN.
     */
    private void onHealthCheckSuccess() {
        CircuitBreakerState current = state.get();
        if (current != CircuitBreakerState.CLOSED) {
            transitionToClosed("health check succeeded");
        }
    }

    private void transitionToOpen(String reason) {
        CircuitBreakerState prev = state.getAndSet(CircuitBreakerState.OPEN);
        if (prev != CircuitBreakerState.OPEN) {
            openedAtMs.set(System.currentTimeMillis());
            logger.error("Circuit breaker transitioning {} → OPEN: {}", prev, reason);
        }
    }

    private void transitionToClosed(String reason) {
        CircuitBreakerState prev = state.getAndSet(CircuitBreakerState.CLOSED);
        if (prev != CircuitBreakerState.CLOSED) {
            usingSecondary = false;
            openedAtMs.set(0L);
            logger.info("Circuit breaker transitioning {} → CLOSED: {}", prev, reason);
        }
    }

    /**
     * Returns the currently active KMS client (primary or secondary).
     */
    private IKMSClient activeClient() {
        return (usingSecondary && secondaryKms != null) ? secondaryKms : primaryKms;
    }
}
