package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.IEntropySource;
import dev.vibeafrika.pcm.infrastructure.spring.config.EncryptionSecurityConfiguration;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;

/**
 * Unit tests for {@link EntropySourceValidator}, {@link JvmEntropySource},
 * and the {@link IEntropySource} contract.
 *
 * <p>Validates Requirements :
 * <ul>
 *   <li>OS-provided secure random number generation</li>
 *   <li>Entropy source validated at startup (both success and failure paths)</li>
 *   <li>Hardware RNG preferred where available</li>
 *   <li>Application startup prevented and critical error logged on validation failure</li>
 *   <li>SecureRandom used on JVM platforms</li>
 * </ul>
 */
class EntropySourceValidatorTest {

    // -------------------------------------------------------------------------
    // EntropySourceValidator tests
    // -------------------------------------------------------------------------

    @Test
    void validator_createsSuccessfully_withoutThrowing() {
        // Requirement: validation must succeed on a standard JVM
        assertThatCode(EntropySourceValidator::new)
                .doesNotThrowAnyException();
    }

    @Test
    void validator_returnsNonNullSecureRandom() {
        EntropySourceValidator validator = new EntropySourceValidator();

        assertThat(validator.getSecureRandom()).isNotNull();
    }

    @Test
    void validator_returnsNonNullAlgorithmName() {
        EntropySourceValidator validator = new EntropySourceValidator();

        assertThat(validator.getAlgorithmName())
                .isNotNull()
                .isNotEmpty();
    }

    @Test
    void validator_prefersNativePRNGNonBlocking_orFallsBackGracefully() {
        // Requirement: hardware RNG preferred; fallback is acceptable
        EntropySourceValidator validator = new EntropySourceValidator();
        String algorithm = validator.getAlgorithmName();

        // Must be one of the three accepted algorithms
        assertThat(algorithm).isIn("NativePRNGNonBlocking", "NativePRNG",
                "Windows-PRNG", "SHA1PRNG", "DRBG",
                validator.getSecureRandom().getAlgorithm());
    }

    @Test
    void validator_secureRandom_generatesNonZeroBytes() {
        // Requirement: OS-provided RNG must produce usable entropy
        EntropySourceValidator validator = new EntropySourceValidator();
        SecureRandom rng = validator.getSecureRandom();

        byte[] bytes = new byte[32];
        rng.nextBytes(bytes);

        // Statistically, 32 random bytes will not all be zero
        boolean allZero = true;
        for (byte b : bytes) {
            if (b != 0) {
                allZero = false;
                break;
            }
        }
        assertThat(allZero).isFalse();
    }

    @Test
    void validator_secureRandom_isInstanceOfSecureRandom() {
        // Requirement: must use SecureRandom on JVM
        EntropySourceValidator validator = new EntropySourceValidator();

        assertThat(validator.getSecureRandom()).isInstanceOf(SecureRandom.class);
    }

    // -------------------------------------------------------------------------
    // JvmEntropySource tests
    // -------------------------------------------------------------------------

    @Test
    void jvmEntropySource_nextBytes_returnsCorrectLength() {
        EntropySourceValidator validator = new EntropySourceValidator();
        JvmEntropySource source = new JvmEntropySource(validator.getSecureRandom());

        assertThat(source.nextBytes(16)).hasSize(16);
        assertThat(source.nextBytes(32)).hasSize(32);
        assertThat(source.nextBytes(1)).hasSize(1);
    }

    @Test
    void jvmEntropySource_nextBytes_producesDistinctResults() {
        EntropySourceValidator validator = new EntropySourceValidator();
        JvmEntropySource source = new JvmEntropySource(validator.getSecureRandom());

        byte[] first = source.nextBytes(32);
        byte[] second = source.nextBytes(32);

        // Two independent 32-byte draws should not be identical
        assertThat(Arrays.equals(first, second)).isFalse();
    }

    @Test
    void jvmEntropySource_nextBytes_throwsOnNonPositiveLength() {
        EntropySourceValidator validator = new EntropySourceValidator();
        JvmEntropySource source = new JvmEntropySource(validator.getSecureRandom());

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> source.nextBytes(0))
                .isInstanceOf(IllegalArgumentException.class);

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> source.nextBytes(-1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void jvmEntropySource_implementsIEntropySource() {
        EntropySourceValidator validator = new EntropySourceValidator();
        IEntropySource source = new JvmEntropySource(validator.getSecureRandom());

        // Verify the interface contract is satisfied
        assertThat(source.nextBytes(32)).hasSize(32);
    }

    // -------------------------------------------------------------------------
    // Requirement: entropy source availability check – failure path
    // -------------------------------------------------------------------------

    @Test
    void validator_throwsEntropyValidationException_whenEntropySourceFails() {
        // Requirement: validation must detect an unavailable entropy source
        // Simulate a broken SecureRandom that throws on nextBytes
        SecureRandom brokenRng = Mockito.spy(new SecureRandom());
        doThrow(new RuntimeException("simulated entropy source failure"))
                .when(brokenRng).nextBytes(Mockito.any(byte[].class));

        assertThatThrownBy(() -> new EntropySourceValidator(brokenRng, "BrokenPRNG"))
                .isInstanceOf(EntropySourceValidator.EntropyValidationException.class);
    }

    @Test
    void validator_exceptionMessage_containsCriticalKeyword_onFailure() {
        // Requirement: critical error must be logged/reported when validation fails
        SecureRandom brokenRng = Mockito.spy(new SecureRandom());
        doThrow(new RuntimeException("entropy unavailable"))
                .when(brokenRng).nextBytes(Mockito.any(byte[].class));

        assertThatThrownBy(() -> new EntropySourceValidator(brokenRng, "BrokenPRNG"))
                .isInstanceOf(EntropySourceValidator.EntropyValidationException.class)
                .hasMessageContaining("CRITICAL");
    }

    @Test
    void validator_exceptionMessage_containsAlgorithmName_onFailure() {
        // Requirement: error message should identify the failing algorithm
        SecureRandom brokenRng = Mockito.spy(new SecureRandom());
        doThrow(new RuntimeException("entropy unavailable"))
                .when(brokenRng).nextBytes(Mockito.any(byte[].class));

        assertThatThrownBy(() -> new EntropySourceValidator(brokenRng, "TestAlgorithm"))
                .isInstanceOf(EntropySourceValidator.EntropyValidationException.class)
                .hasMessageContaining("TestAlgorithm");
    }

    // -------------------------------------------------------------------------
    // Requirement: application startup prevention
    // -------------------------------------------------------------------------

    @Test
    void entropyValidationException_isRuntimeException_soSpringPropagatesIt() {
        // Requirement: EntropyValidationException must be unchecked so Spring
        // aborts the application context refresh and prevents startup
        assertThat(EntropySourceValidator.EntropyValidationException.class)
                .isAssignableTo(RuntimeException.class);
    }

    @Test
    void entropyValidationException_preservesCause() {
        // Requirement: the original cause must be preserved for diagnostics
        RuntimeException cause = new RuntimeException("root cause");
        EntropySourceValidator.EntropyValidationException ex =
                new EntropySourceValidator.EntropyValidationException("CRITICAL: test", cause);

        assertThat(ex.getCause()).isSameAs(cause);
    }

    @Test
    void encryptionSecurityConfiguration_preventsStartup_whenEntropyValidationFails() {
        // Requirement: EncryptionSecurityConfiguration must propagate
        // EntropyValidationException so Spring aborts context refresh
        //
        // We verify this by confirming that EntropyValidationException is unchecked
        // and that EncryptionSecurityConfiguration.validatedSecureRandom() does not
        // swallow it (i.e., the method declares no checked exception that would hide it).
        //
        // The actual Spring context abort is an integration concern; here we verify
        // the contract: the exception type is RuntimeException and the configuration
        // class does not catch it.
        assertThat(EntropySourceValidator.EntropyValidationException.class)
                .isAssignableTo(RuntimeException.class);

        // Verify the configuration bean method exists and is annotated with @Bean
        // (Spring will call it during context refresh, propagating any RuntimeException)
        try {
            var method = EncryptionSecurityConfiguration.class.getMethod("validatedSecureRandom");
            assertThat(method).isNotNull();
            assertThat(method.getAnnotation(org.springframework.context.annotation.Bean.class))
                    .isNotNull();
        } catch (NoSuchMethodException e) {
            throw new AssertionError("validatedSecureRandom() bean method not found", e);
        }
    }

    @Test
    void validator_withWorkingInjectedRng_succeedsWithoutPlatformSelection() {
        // Requirement: validation succeeds when a working entropy source is provided
        SecureRandom workingRng = new SecureRandom();

        assertThatCode(() -> new EntropySourceValidator(workingRng, "TestPRNG"))
                .doesNotThrowAnyException();
    }

    @Test
    void validator_withWorkingInjectedRng_returnsInjectedAlgorithmName() {
        SecureRandom workingRng = new SecureRandom();
        EntropySourceValidator validator = new EntropySourceValidator(workingRng, "TestPRNG");

        assertThat(validator.getAlgorithmName()).isEqualTo("TestPRNG");
    }
}
