package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.AlgorithmCompatibilityMatrix;
import dev.vibeafrika.pcm.domain.encryption.EncryptionAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link AlgorithmCompatibilityMatrix}.
 *
 * <p>Covers default compatibility rules and dynamic registration.
 */
class AlgorithmCompatibilityMatrixTest {

    private AlgorithmCompatibilityMatrix matrix;

    @BeforeEach
    void setUp() {
        matrix = new AlgorithmCompatibilityMatrix();
    }

    @Test
    @DisplayName("default matrix: AES_256_GCM can decrypt AES_256_GCM ciphertext")
    void defaultMatrix_gcmCanDecryptGcm() {
        assertTrue(matrix.canDecrypt(EncryptionAlgorithm.AES_256_GCM, EncryptionAlgorithm.AES_256_GCM));
    }

    @Test
    @DisplayName("default matrix: AES_256_CBC_HMAC can decrypt AES_256_CBC_HMAC ciphertext")
    void defaultMatrix_cbcHmacCanDecryptCbcHmac() {
        assertTrue(matrix.canDecrypt(EncryptionAlgorithm.AES_256_CBC_HMAC, EncryptionAlgorithm.AES_256_CBC_HMAC));
    }

    @Test
    @DisplayName("default matrix: AES_256_GCM can decrypt AES_256_CBC_HMAC ciphertext (migration compatibility)")
    void defaultMatrix_gcmCanDecryptCbcHmac() {
        // Migration compatibility: GCM can decrypt CBC_HMAC ciphertext
        assertTrue(matrix.canDecrypt(EncryptionAlgorithm.AES_256_CBC_HMAC, EncryptionAlgorithm.AES_256_GCM));
    }

    @Test
    @DisplayName("register adds a new compatibility entry")
    void register_addsNewCompatibility() {
        // Initially CBC_HMAC cannot decrypt GCM ciphertext
        assertFalse(matrix.canDecrypt(EncryptionAlgorithm.AES_256_GCM, EncryptionAlgorithm.AES_256_CBC_HMAC));

        matrix.register(EncryptionAlgorithm.AES_256_GCM, EncryptionAlgorithm.AES_256_CBC_HMAC);

        assertTrue(matrix.canDecrypt(EncryptionAlgorithm.AES_256_GCM, EncryptionAlgorithm.AES_256_CBC_HMAC));
    }

    @Test
    @DisplayName("canDecrypt returns false for unregistered pair")
    void canDecrypt_returnsFalseForUnregisteredPair() {
        // GCM ciphertext cannot be decrypted by CBC_HMAC by default
        assertFalse(matrix.canDecrypt(EncryptionAlgorithm.AES_256_GCM, EncryptionAlgorithm.AES_256_CBC_HMAC));
    }

    @Test
    @DisplayName("getCompatibleDecryptors returns the correct set for AES_256_CBC_HMAC")
    void getCompatibleDecryptors_returnsCorrectSet() {
        Set<EncryptionAlgorithm> decryptors =
                matrix.getCompatibleDecryptors(EncryptionAlgorithm.AES_256_CBC_HMAC);

        // Both CBC_HMAC itself and GCM can decrypt CBC_HMAC ciphertext (default rules)
        assertTrue(decryptors.contains(EncryptionAlgorithm.AES_256_CBC_HMAC),
                "CBC_HMAC should be able to decrypt its own ciphertext");
        assertTrue(decryptors.contains(EncryptionAlgorithm.AES_256_GCM),
                "GCM should be able to decrypt CBC_HMAC ciphertext (migration compatibility)");
    }
}
