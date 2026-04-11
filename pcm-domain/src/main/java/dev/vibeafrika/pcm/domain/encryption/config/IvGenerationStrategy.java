package dev.vibeafrika.pcm.domain.encryption.config;

/**
 * Strategy for generating Initialization Vectors (IVs).
 *
 * <p>{@link #COUNTER_BASED} uses a monotonically increasing counter combined with
 * a random base value to guarantee IV uniqueness without relying solely on random
 * number generation.
 */
public enum IvGenerationStrategy {
    COUNTER_BASED
}
