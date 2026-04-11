package dev.vibeafrika.pcm.domain.encryption.config;

import java.util.Objects;

/**
 * Configuration for the circuit-breaker protecting KMS/network calls.
 *
 * <p>The circuit breaker opens after {@link #failureThreshold} consecutive
 * failures, waits {@link #recoveryTimeSeconds} seconds before moving to
 * half-open state, and allows at most {@link #halfOpenMaxCalls} probe calls
 * before deciding whether to close or re-open.
 */
public record CircuitBreakerConfig(
        int failureThreshold,
        int recoveryTimeSeconds,
        int halfOpenMaxCalls
) {
    public CircuitBreakerConfig {
        if (failureThreshold < 1) {
            throw new IllegalArgumentException("failureThreshold must be >= 1");
        }
        if (recoveryTimeSeconds < 0) {
            throw new IllegalArgumentException("recoveryTimeSeconds must be >= 0");
        }
        if (halfOpenMaxCalls < 1) {
            throw new IllegalArgumentException("halfOpenMaxCalls must be >= 1");
        }
    }
}
