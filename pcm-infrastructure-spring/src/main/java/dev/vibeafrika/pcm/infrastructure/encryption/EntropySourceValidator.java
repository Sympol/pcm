package dev.vibeafrika.pcm.infrastructure.encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Validates and provides a cryptographically secure entropy source at application startup.
 *
 * <p>Implements Specify CSPRNG Source:
 * <ul>
 *   <li>Uses operating-system-provided secure random number generation</li>
 *   <li>Prohibits custom PRNG implementations</li>
 *   <li>Validates entropy source availability at startup</li>
 *   <li>Prefers hardware RNG ({@code NativePRNGNonBlocking}) where available</li>
 *   <li>Prevents application startup and logs CRITICAL error if validation fails</li>
 *   <li>Uses {@link SecureRandom} on JVM platforms</li>
 * </ul>
 *
 * <p>Algorithm selection order (most preferred first):
 * <ol>
 *   <li>{@code NativePRNGNonBlocking} – hardware-backed, non-blocking OS entropy</li>
 *   <li>{@code NativePRNG} – OS entropy (may block on low-entropy systems)</li>
 *   <li>Default {@link SecureRandom} – JVM default (platform-specific)</li>
 * </ol>
 *
 * <p>This is a plain class with no Spring dependencies; it is instantiated and
 * validated by {@link EncryptionSecurityConfiguration} before being exposed as a bean.
 */
public final class EntropySourceValidator {

    private static final Logger logger = LoggerFactory.getLogger(EntropySourceValidator.class);

    /** Number of test bytes generated to confirm the entropy source is functional. */
    private static final int VALIDATION_BYTE_COUNT = 32;

    private final SecureRandom secureRandom;
    private final String algorithmName;

    /**
     * Creates and validates the entropy source.
     *
     * <p>Attempts to obtain a {@link SecureRandom} instance in preference order,
     * generates {@value #VALIDATION_BYTE_COUNT} test bytes to confirm functionality,
     * and logs the selected algorithm at INFO level.
     *
     * @throws EntropyValidationException if no functional entropy source can be obtained
     */
    public EntropySourceValidator() {
        this(null, null);
    }

    /**
     * Package-private constructor for testing: validates the supplied {@link SecureRandom}
     * instead of selecting one from the platform.
     *
     * <p>Pass {@code null} for both parameters to use the normal platform-selection logic.
     * Pass a non-null {@code rng} to skip platform selection and validate the supplied
     * instance directly (useful for injecting a broken stub in unit tests).
     *
     * @param rng       the {@link SecureRandom} to validate, or {@code null} to use platform selection
     * @param algorithm the algorithm name to record, or {@code null} when {@code rng} is {@code null}
     * @throws EntropyValidationException if the supplied or selected entropy source fails validation
     */
    EntropySourceValidator(SecureRandom injectedRng, String injectedAlgorithm) {
        SecureRandom rng = injectedRng;
        String algorithm = injectedAlgorithm;

        if (rng == null) {
            // 1. Try hardware-backed non-blocking OS entropy 
            try {
                rng = SecureRandom.getInstance("NativePRNGNonBlocking");
                algorithm = "NativePRNGNonBlocking";
                logger.info("Entropy source: NativePRNGNonBlocking (hardware-backed, non-blocking)");
            } catch (NoSuchAlgorithmException e) {
                logger.debug("NativePRNGNonBlocking not available on this platform, trying NativePRNG");
            }

            // 2. Fall back to NativePRNG (OS entropy, may block)
            if (rng == null) {
                try {
                    rng = SecureRandom.getInstance("NativePRNG");
                    algorithm = "NativePRNG";
                    logger.info("Entropy source: NativePRNG (OS entropy)");
                } catch (NoSuchAlgorithmException e) {
                    logger.debug("NativePRNG not available on this platform, using default SecureRandom");
                }
            }

            // 3. Fall back to JVM default SecureRandom 
            if (rng == null) {
                rng = new SecureRandom();
                algorithm = rng.getAlgorithm();
                logger.info("Entropy source: default SecureRandom (algorithm={})", algorithm);
            }
        }

        // Validate the selected source by generating test bytes
        try {
            byte[] testBytes = new byte[VALIDATION_BYTE_COUNT];
            rng.nextBytes(testBytes);
            logger.info("Entropy source validation passed: algorithm={}, test={} bytes generated",
                    algorithm, VALIDATION_BYTE_COUNT);
        } catch (Exception e) {
            String msg = "CRITICAL: Entropy source validation failed – application startup prevented. " +
                         "Algorithm: " + algorithm + ". Cause: " + e.getMessage();
            logger.error(msg, e);
            //prevent application startup
            throw new EntropyValidationException(msg, e);
        }

        this.secureRandom = rng;
        this.algorithmName = algorithm;
    }

    /**
     * Returns the validated {@link SecureRandom} instance.
     *
     * @return the validated entropy source; never {@code null}
     */
    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    /**
     * Returns the algorithm name of the selected entropy source.
     *
     * @return the algorithm name (e.g. {@code "NativePRNGNonBlocking"}); never {@code null}
     */
    public String getAlgorithmName() {
        return algorithmName;
    }

    /**
     * Thrown when the entropy source cannot be validated at startup.
     *
     * <p>This is an unchecked exception so that it propagates through Spring's
     * bean initialization and prevents the application context from starting
     */
    public static final class EntropyValidationException extends RuntimeException {

        public EntropyValidationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
