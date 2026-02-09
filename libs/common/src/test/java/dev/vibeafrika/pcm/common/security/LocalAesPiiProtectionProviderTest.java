package dev.vibeafrika.pcm.common.security;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LocalAesPiiProtectionProviderTest {

    private final String VALID_SECRET = "1234567890123456"; // 16 chars

    @Test
    void shouldEncryptAndDecryptSuccessfully() {
        LocalAesPiiProtectionProvider provider = new LocalAesPiiProtectionProvider(VALID_SECRET);
        String original = "sensitive data";

        String encrypted = provider.encrypt(original);
        assertThat(encrypted).startsWith("local:v1:");
        assertThat(encrypted).isNotEqualTo(original);

        String decrypted = provider.decrypt(encrypted);
        assertThat(decrypted).isEqualTo(original);
    }

    @Test
    void shouldReturnSameValueIfNullOrEmpty() {
        LocalAesPiiProtectionProvider provider = new LocalAesPiiProtectionProvider(VALID_SECRET);

        assertThat(provider.encrypt(null)).isNull();
        assertThat(provider.encrypt("")).isEmpty();
        assertThat(provider.decrypt(null)).isNull();
    }

    @Test
    void shouldNotDecryptIfPrefixMissing() {
        LocalAesPiiProtectionProvider provider = new LocalAesPiiProtectionProvider(VALID_SECRET);
        String notEncrypted = "some-text";

        assertThat(provider.decrypt(notEncrypted)).isEqualTo(notEncrypted);
    }

    @Test
    void shouldThrowExceptionIfSecretInvalid() {
        assertThatThrownBy(() -> new LocalAesPiiProtectionProvider("too-short"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
