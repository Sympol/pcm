package dev.vibeafrika.pcm.infrastructure.encryption;

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Unit tests for {@link HardwareAccelerationConfig}.
 *
 * <p>Validates that AES-NI detection and provider resolution work correctly
 * without throwing exceptions.
 */
class HardwareAccelerationConfigTest {

    @Test
    void isAesNiAvailable_returnsBoolean_withoutThrowing() {
        // Should never throw — detection is best-effort
        assertThatCode(HardwareAccelerationConfig::isAesNiAvailable)
                .doesNotThrowAnyException();

        boolean result = HardwareAccelerationConfig.isAesNiAvailable();
        // Result is a valid boolean (trivially true, but documents the contract)
        assertThat(result).isIn(true, false);
    }

    @Test
    void getPreferredProvider_returnsNonNullNonEmptyString() {
        String provider = HardwareAccelerationConfig.getPreferredProvider();

        assertThat(provider)
                .isNotNull()
                .isNotEmpty();
    }

    @Test
    void detectedProvider_canCreateAesGcmCipher() throws Exception {
        String providerName = HardwareAccelerationConfig.getPreferredProvider();

        // The reported provider must be able to instantiate AES/GCM/NoPadding
        Cipher cipher;
        if ("default".equals(providerName)) {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
        } else {
            cipher = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        }

        assertThat(cipher).isNotNull();
        assertThat(cipher.getAlgorithm()).isEqualTo("AES/GCM/NoPadding");
    }

    @Test
    void detect_returnsConfiguredInstance() {
        HardwareAccelerationConfig config = HardwareAccelerationConfig.detect();

        assertThat(config).isNotNull();
        assertThat(config.getProvider()).isNotNull().isNotEmpty();
        // isAesNiDetected() must agree with the static method
        assertThat(config.isAesNiDetected()).isEqualTo(HardwareAccelerationConfig.isAesNiAvailable());
    }
}
