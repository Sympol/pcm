package dev.vibeafrika.pcm.infrastructure.spring.config;

import dev.vibeafrika.pcm.domain.encryption.IEntropySource;
import dev.vibeafrika.pcm.infrastructure.encryption.EntropySourceValidator;
import dev.vibeafrika.pcm.infrastructure.encryption.JvmEntropySource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.SecureRandom;

/**
 * Spring configuration for cryptographic security primitives.
 *
 * <p>Validates the OS-backed entropy source at startup and exposes the validated
 * {@link SecureRandom} and {@link IEntropySource} as injectable Spring beans.
 *
 * <p>Implements Specify CSPRNG Source :
 * <ul>
 *   <li> OS-provided secure random number generation</li>
 *   <li> No custom PRNG implementations</li>
 *   <li> Entropy source validated at startup via {@link EntropySourceValidator}</li>
 *   <li> Hardware RNG preferred ({@code NativePRNGNonBlocking})</li>
 *   <li> Application startup prevented if validation fails</li>
 *   <li> {@link SecureRandom} used on JVM platforms</li>
 * </ul>
 *
 * <p>If {@link EntropySourceValidator} throws during bean creation, Spring will
 * propagate the exception and abort the application context refresh, preventing
 * the application from starting (Requirement 22.5).
 */
@Configuration
public class EncryptionSecurityConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionSecurityConfiguration.class);

    /**
     * Creates and validates the entropy source, then exposes the validated
     * {@link SecureRandom} as a Spring bean.
     *
     * <p>The {@link EntropySourceValidator} constructor performs the validation:
     * it selects the best available OS-backed algorithm, generates test bytes,
     * and throws {@link EntropySourceValidator.EntropyValidationException} on failure.
     *
     * @return the validated {@link SecureRandom} instance
     * @throws EntropySourceValidator.EntropyValidationException if entropy source is unavailable
     */
    @Bean
    public SecureRandom validatedSecureRandom() {
        logger.info("Initializing and validating cryptographic entropy source");
        EntropySourceValidator validator = new EntropySourceValidator();
        logger.info("Entropy source ready: algorithm={}", validator.getAlgorithmName());
        return validator.getSecureRandom();
    }

    /**
     * Creates the {@link IEntropySource} bean backed by the validated {@link SecureRandom}.
     *
     * <p>Inject {@link IEntropySource} into components that need cryptographically
     * secure random bytes without taking a direct dependency on {@link SecureRandom}
     * or Spring.
     *
     * @param secureRandom the validated entropy source produced by {@link #validatedSecureRandom()}
     * @return the {@link JvmEntropySource} implementation
     */
    @Bean
    public IEntropySource entropySource(SecureRandom secureRandom) {
        return new JvmEntropySource(secureRandom);
    }
}
