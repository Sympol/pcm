package dev.vibeafrika.pcm.domain.encryption.config;

/**
 * FIPS 140-2 certification levels for KMS solutions.
 *
 * <p>Production environments require a minimum of {@link #FIPS_140_2_L3}.
 * Non-critical environments may use {@link #FIPS_140_2_L2}.
 */
public enum FipsLevel {
    FIPS_140_2_L2,
    FIPS_140_2_L3
}
