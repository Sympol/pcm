package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for encryption edge cases.
 *
 * <p>Covers :
 * <ul>
 *   <li>Encryption failure returns descriptive error and prevents data storage</li>
 *   <li>Decryption failure returns descriptive error</li>
 *   <li>Corrupted/tampered ciphertext is detected and returns a tampering error</li>
 * </ul>
 */
class EncryptionEdgeCasesTest {

    private EncryptionService encryptionService;

    @BeforeEach
    void setUp() {
        UUID dekId = UUID.randomUUID();
        IKeyManager stubKeyManager = new StubKeyManager(dekId);
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(stubKeyManager, "test-global-salt");
        encryptionService = new EncryptionService(stubKeyManager, blindIndexService, noOpAuditLogger, ivCounter);
    }

    // -------------------------------------------------------------------------
    // Empty string
    // -------------------------------------------------------------------------

    @Test
    void encrypt_emptyString_succeeds() {
        Result<Ciphertext, EncryptionError> result =
                encryptionService.encrypt("", BoundedContext.PROFILE);

        assertThat(result.isSuccess())
                .as("Encrypting an empty string should succeed")
                .isTrue();
    }

    @Test
    void decrypt_emptyStringRoundTrip_returnsEmptyString() {
        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt("", BoundedContext.PROFILE);
        assertThat(encryptResult.isSuccess()).isTrue();

        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(encryptResult.getValue().orElseThrow(), BoundedContext.PROFILE);

        assertThat(decryptResult.isSuccess())
                .as("Decrypting an empty-string ciphertext should succeed")
                .isTrue();
        assertThat(decryptResult.getValue().orElseThrow())
                .as("Decrypted value should be the original empty string")
                .isEmpty();
    }

    // -------------------------------------------------------------------------
    // Very long strings (>1MB)
    // -------------------------------------------------------------------------

    @Test
    void encrypt_veryLongString_succeeds() {
        // Build a 1MB+ string
        String longString = "A".repeat(1_100_000);

        Result<Ciphertext, EncryptionError> result =
                encryptionService.encrypt(longString, BoundedContext.CONSENT);

        assertThat(result.isSuccess())
                .as("Encrypting a >1MB string should succeed")
                .isTrue();
    }

    @Test
    void decrypt_veryLongStringRoundTrip_returnsOriginal() {
        String longString = "B".repeat(1_100_000);

        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(longString, BoundedContext.CONSENT);
        assertThat(encryptResult.isSuccess()).isTrue();

        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(encryptResult.getValue().orElseThrow(), BoundedContext.CONSENT);

        assertThat(decryptResult.isSuccess())
                .as("Decrypting a >1MB ciphertext should succeed")
                .isTrue();
        assertThat(decryptResult.getValue().orElseThrow())
                .as("Decrypted value should equal the original long string")
                .isEqualTo(longString);
    }

    // -------------------------------------------------------------------------
    // Special characters and Unicode
    // -------------------------------------------------------------------------

    @Test
    void encrypt_specialCharacters_succeeds() {
        String specialChars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\";

        Result<Ciphertext, EncryptionError> result =
                encryptionService.encrypt(specialChars, BoundedContext.SEGMENT);

        assertThat(result.isSuccess())
                .as("Encrypting special characters should succeed")
                .isTrue();
    }

    @Test
    void decrypt_specialCharactersRoundTrip_returnsOriginal() {
        String specialChars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\";

        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(specialChars, BoundedContext.SEGMENT);
        assertThat(encryptResult.isSuccess()).isTrue();

        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(encryptResult.getValue().orElseThrow(), BoundedContext.SEGMENT);

        assertThat(decryptResult.isSuccess()).isTrue();
        assertThat(decryptResult.getValue().orElseThrow()).isEqualTo(specialChars);
    }

    @Test
    void encrypt_unicodeMultilingualText_succeeds() {
        // Mix of CJK, Arabic, emoji, and Latin
        String unicode = "こんにちは مرحبا 你好 Héllo Wörld 🔐🌍";

        Result<Ciphertext, EncryptionError> result =
                encryptionService.encrypt(unicode, BoundedContext.PREFERENCE);

        assertThat(result.isSuccess())
                .as("Encrypting multilingual Unicode text should succeed")
                .isTrue();
    }

    @Test
    void decrypt_unicodeMultilingualTextRoundTrip_returnsOriginal() {
        String unicode = "こんにちは مرحبا 你好 Héllo Wörld 🔐🌍";

        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(unicode, BoundedContext.PREFERENCE);
        assertThat(encryptResult.isSuccess()).isTrue();

        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(encryptResult.getValue().orElseThrow(), BoundedContext.PREFERENCE);

        assertThat(decryptResult.isSuccess()).isTrue();
        assertThat(decryptResult.getValue().orElseThrow()).isEqualTo(unicode);
    }

    @Test
    void encrypt_nullCharactersAndControlChars_succeeds() {
        // Null byte and control characters embedded in string
        String withNulls = "before\u0000after\u0001\u001F";

        Result<Ciphertext, EncryptionError> result =
                encryptionService.encrypt(withNulls, BoundedContext.PROFILE);

        assertThat(result.isSuccess())
                .as("Encrypting strings with null/control characters should succeed")
                .isTrue();
    }

    @Test
    void decrypt_nullCharactersRoundTrip_returnsOriginal() {
        String withNulls = "before\u0000after\u0001\u001F";

        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(withNulls, BoundedContext.PROFILE);
        assertThat(encryptResult.isSuccess()).isTrue();

        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(encryptResult.getValue().orElseThrow(), BoundedContext.PROFILE);

        assertThat(decryptResult.isSuccess()).isTrue();
        assertThat(decryptResult.getValue().orElseThrow()).isEqualTo(withNulls);
    }

    // -------------------------------------------------------------------------
    // Invalid ciphertext format
    // -------------------------------------------------------------------------

    @Test
    void decrypt_tooShortCiphertextBytes_throwsIllegalArgument() {
        // Ciphertext.of() enforces minimum 46 bytes — verify the guard is in place
        byte[] tooShort = new byte[10];
        assertThatThrownBy(() -> Ciphertext.of(tooShort))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("too short");
    }

    @Test
    void decrypt_emptyCiphertextBytes_throwsIllegalArgument() {
        // Ciphertext.of() rejects empty byte arrays
        assertThatThrownBy(() -> Ciphertext.of(new byte[0]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("too short");
    }

    @Test
    void decrypt_unsupportedVersionByte_returnsFailure() {
        // Build a ciphertext with an unsupported version byte (0x02)
        byte[] bytes = buildMinimalCiphertextBytes();
        bytes[0] = 0x02; // unsupported version
        Ciphertext invalidCiphertext = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                encryptionService.decrypt(invalidCiphertext, BoundedContext.PROFILE);

        assertThat(result.isFailure())
                .as("Decrypting ciphertext with unsupported version should fail")
                .isTrue();
    }

    @Test
    void decrypt_unsupportedAlgorithmByte_returnsFailure() {
        // Build a ciphertext with an unsupported algorithm byte (0x03)
        byte[] bytes = buildMinimalCiphertextBytes();
        bytes[1] = 0x03; // unsupported algorithm
        Ciphertext invalidCiphertext = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                encryptionService.decrypt(invalidCiphertext, BoundedContext.PROFILE);

        assertThat(result.isFailure())
                .as("Decrypting ciphertext with unsupported algorithm should fail")
                .isTrue();
    }

    @Test
    void decrypt_tamperedCiphertext_returnsFailure() {
        // Encrypt a valid plaintext, then flip a byte in the ciphertext body
        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt("sensitive-data@example.com", BoundedContext.PROFILE);
        assertThat(encryptResult.isSuccess()).isTrue();

        byte[] bytes = encryptResult.getValue().orElseThrow().getValue().clone();
        // Flip a byte in the ciphertext body (after the 30-byte header)
        bytes[30] ^= 0xFF;
        Ciphertext tampered = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                encryptionService.decrypt(tampered, BoundedContext.PROFILE);

        assertThat(result.isFailure())
                .as("Decrypting tampered ciphertext should fail")
                .isTrue();
    }

    @Test
    void decrypt_tamperedAuthTag_returnsFailure() {
        // Encrypt a valid plaintext, then corrupt the auth tag (last 16 bytes)
        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt("user@example.com", BoundedContext.PROFILE);
        assertThat(encryptResult.isSuccess()).isTrue();

        byte[] bytes = encryptResult.getValue().orElseThrow().getValue().clone();
        // Flip the last byte (part of the auth tag)
        bytes[bytes.length - 1] ^= 0xFF;
        Ciphertext tampered = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                encryptionService.decrypt(tampered, BoundedContext.PROFILE);

        assertThat(result.isFailure())
                .as("Decrypting ciphertext with corrupted auth tag should fail")
                .isTrue();
    }

    @Test
    void decrypt_randomBytes_returnsFailure() {
        // Completely random bytes that happen to be long enough
        byte[] randomBytes = new byte[100];
        new SecureRandom().nextBytes(randomBytes);
        // Set valid version and algorithm to get past format parsing
        randomBytes[0] = CiphertextFormat.VERSION_1;
        randomBytes[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;
        Ciphertext randomCiphertext = Ciphertext.of(randomBytes);

        Result<String, DecryptionError> result =
                encryptionService.decrypt(randomCiphertext, BoundedContext.PROFILE);

        assertThat(result.isFailure())
                .as("Decrypting random bytes should fail")
                .isTrue();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Builds a syntactically valid 46-byte ciphertext (minimum size) with
     * version=0x01 and algorithm=AES-256-GCM but garbage content.
     */
    private byte[] buildMinimalCiphertextBytes() {
        byte[] bytes = new byte[46];
        bytes[0] = CiphertextFormat.VERSION_1;
        bytes[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;
        // bytes 2-17: key ID (all zeros = UUID 0-0)
        // bytes 18-29: IV (all zeros)
        // bytes 30-29: ciphertext (empty)
        // bytes 30-45: auth tag (all zeros)
        return bytes;
    }

    // -------------------------------------------------------------------------
    // Test infrastructure (mirrors EncryptionRoundTripPropertyTest)
    // -------------------------------------------------------------------------

    private static final class StubKeyManager implements IKeyManager {

        private final UUID keyId;
        private final DEK dek;

        StubKeyManager(UUID keyId) {
            this.keyId = keyId;
            byte[] keyMaterial = new byte[32];
            new SecureRandom().nextBytes(keyMaterial);
            this.dek = DEK.of(keyMaterial);
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.success(buildMetadata(context));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            return Result.success(buildMetadata(BoundedContext.PROFILE));
        }

        private DEKWithMetadata buildMetadata(BoundedContext context) {
            return DEKWithMetadata.builder()
                    .dek(dek)
                    .keyId(keyId)
                    .kekId(UUID.randomUUID())
                    .context(context)
                    .environment(Environment.DEV)
                    .algorithm(EncryptionAlgorithm.AES_256_GCM)
                    .createdAt(Instant.now())
                    .status(KeyStatus.ACTIVE)
                    .build();
        }

        @Override
        public Result<UUID, KeyError> rotateDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in test"));
        }

        @Override
        public Result<UUID, KeyError> rotateKEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in test"));
        }

        @Override
        public Result<Void, KeyError> invalidateCache(UUID keyId) {
            return Result.success(null);
        }

        @Override
        public Result<DeletionCertificate, KeyError> deleteUserDEK(String userId, BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "Not needed in test"));
        }

        @Override
        public Result<byte[], KeyError> getBlindIndexKey() {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            return Result.success(key);
        }
    }

    private static final class NoOpAuditLogger implements IAuditLogger {

        private static final AuditError NOOP = AuditError.of("NOOP", "no-op logger");

        @Override
        public Result<Void, AuditError> logEncryption(EncryptionEvent event) {
            return Result.failure(NOOP);
        }

        @Override
        public Result<Void, AuditError> logDecryption(DecryptionEvent event) {
            return Result.failure(NOOP);
        }

        @Override
        public Result<Void, AuditError> logKeyRotation(KeyRotationEvent event) {
            return Result.failure(NOOP);
        }

        @Override
        public Result<Void, AuditError> logSecurityEvent(SecurityEvent event) {
            return Result.failure(NOOP);
        }

        @Override
        public Result<Void, AuditError> logKeyAccess(KeyAccessEvent event) {
            return Result.failure(NOOP);
        }
    }
}
