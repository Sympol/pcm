package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for error handling in EncryptionService.
 *
 * <ul>
 *   <li>Encryption failures return descriptive errors and prevent data persistence</li>
 *   <li>Decryption failures return descriptive errors</li>
 *   <li>Corrupted/tampered ciphertext is detected; tampering is distinguished from corruption</li>
 *   <li>Error messages do not expose sensitive details (no plaintext PII, no key material)</li>
 * </ul>
 */
class EncryptionServiceErrorHandlingTest {

    // =========================================================================
    // Encryption failures return descriptive errors
    // =========================================================================

    @Test
    void encrypt_whenKeyUnavailable_returnsDescriptiveError() {
        // Arrange: key manager that always fails
        EncryptionService service = buildServiceWithFailingKeyManager();

        // Act
        Result<Ciphertext, EncryptionError> result =
                service.encrypt("user@example.com", BoundedContext.PROFILE);

        // Assert: failure with a meaningful code
        assertThat(result.isFailure()).isTrue();
        EncryptionError error = result.getError().orElseThrow();
        assertThat(error.getCode())
                .as("Key unavailability must produce KEY_UNAVAILABLE error code")
                .isEqualTo(EncryptionErrorCodes.KEY_UNAVAILABLE.code());
        assertThat(error.getMessage())
                .as("Error message must be non-blank")
                .isNotBlank();
    }

    @Test
    void encrypt_whenKeyUnavailable_returnsFailureNotNull() {
        // Encryption failure must return a Result.failure, never null
        EncryptionService service = buildServiceWithFailingKeyManager();

        Result<Ciphertext, EncryptionError> result =
                service.encrypt("sensitive-data", BoundedContext.CONSENT);

        assertThat(result).isNotNull();
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getError()).isPresent();
    }

    @Test
    void encryptBatch_whenKeyUnavailable_returnsDescriptiveError() {
        EncryptionService service = buildServiceWithFailingKeyManager();

        Result<List<Ciphertext>, EncryptionError> result =
                service.encryptBatch(List.of("a@b.com", "+15551234567"), BoundedContext.PROFILE);

        assertThat(result.isFailure()).isTrue();
        EncryptionError error = result.getError().orElseThrow();
        assertThat(error.getCode()).isEqualTo(EncryptionErrorCodes.KEY_UNAVAILABLE.code());
    }

    // =========================================================================
    // Encryption failure prevents data persistence
    // (The Result type enforces this: callers cannot obtain a Ciphertext on failure)
    // =========================================================================

    @Test
    void encrypt_onFailure_ciphertextValueIsAbsent() {
        // When encryption fails, the Result must not carry a ciphertext value.
        // This is the mechanism that prevents accidental persistence of plaintext.
        EncryptionService service = buildServiceWithFailingKeyManager();

        Result<Ciphertext, EncryptionError> result =
                service.encrypt("user@example.com", BoundedContext.PROFILE);

        assertThat(result.isFailure()).isTrue();
        assertThat(result.getValue())
                .as("No ciphertext value must be present on encryption failure")
                .isEmpty();
    }

    // =========================================================================
    // Decryption failures return descriptive errors
    // =========================================================================

    @Test
    void decrypt_whenKeyNotFound_returnsDescriptiveError() {
        // Arrange: key manager that fails on getDEK (simulates rotated/deleted key)
        EncryptionService service = buildServiceWithKeyNotFoundOnDecrypt();

        // Build a syntactically valid ciphertext (version + algorithm + zeros)
        byte[] bytes = buildMinimalCiphertextBytes();
        Ciphertext ciphertext = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                service.decrypt(ciphertext, BoundedContext.PROFILE);

        assertThat(result.isFailure()).isTrue();
        DecryptionError error = result.getError().orElseThrow();
        assertThat(error.getCode())
                .as("Missing key must produce KEY_NOT_FOUND error code")
                .isEqualTo(EncryptionErrorCodes.KEY_NOT_FOUND.code());
        assertThat(error.getMessage()).isNotBlank();
    }

    @Test
    void decrypt_withInvalidCiphertextFormat_returnsDescriptiveError() {
        EncryptionService service = buildNormalService();

        // Unsupported version byte
        byte[] bytes = buildMinimalCiphertextBytes();
        bytes[0] = 0x7F; // unsupported version
        Ciphertext ciphertext = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                service.decrypt(ciphertext, BoundedContext.PROFILE);

        assertThat(result.isFailure()).isTrue();
        assertThat(result.getError().orElseThrow().getMessage()).isNotBlank();
    }

    @Test
    void decrypt_withUnsupportedAlgorithm_returnsDescriptiveError() {
        EncryptionService service = buildNormalService();

        byte[] bytes = buildMinimalCiphertextBytes();
        bytes[1] = 0x7F; // unsupported algorithm
        Ciphertext ciphertext = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                service.decrypt(ciphertext, BoundedContext.PROFILE);

        assertThat(result.isFailure()).isTrue();
        DecryptionError error = result.getError().orElseThrow();
        assertThat(error.getCode())
                .isEqualTo(EncryptionErrorCodes.UNSUPPORTED_ALGORITHM.code());
    }

    @Test
    void decryptBatch_whenOneCiphertextIsInvalid_returnsDescriptiveError() {
        EncryptionService service = buildNormalService();

        // Encrypt one valid value
        Result<Ciphertext, EncryptionError> enc =
                service.encrypt("valid@example.com", BoundedContext.PROFILE);
        assertThat(enc.isSuccess()).isTrue();

        // Build an invalid ciphertext (tampered auth tag)
        byte[] bytes = enc.getValue().orElseThrow().getValue().clone();
        bytes[bytes.length - 1] ^= 0xFF;
        Ciphertext tampered = Ciphertext.of(bytes);

        Result<List<String>, DecryptionError> result =
                service.decryptBatch(List.of(enc.getValue().orElseThrow(), tampered), BoundedContext.PROFILE);

        assertThat(result.isFailure()).isTrue();
        assertThat(result.getError().orElseThrow().getMessage()).isNotBlank();
    }

    // =========================================================================
    // Distinguish tampering from corruption/format errors
    // =========================================================================

    @Test
    void decrypt_whenAuthTagTampered_returnsTamperingDetectedCode() {
        EncryptionService service = buildNormalService();

        Result<Ciphertext, EncryptionError> enc =
                service.encrypt("user@example.com", BoundedContext.PROFILE);
        assertThat(enc.isSuccess()).isTrue();

        // Flip the last byte (auth tag)
        byte[] bytes = enc.getValue().orElseThrow().getValue().clone();
        bytes[bytes.length - 1] ^= 0xFF;
        Ciphertext tampered = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                service.decrypt(tampered, BoundedContext.PROFILE);

        assertThat(result.isFailure()).isTrue();
        assertThat(result.getError().orElseThrow().getCode())
                .as("Auth tag failure must be reported as TAMPERING_DETECTED, not generic DECRYPTION_FAILED")
                .isEqualTo(EncryptionErrorCodes.TAMPERING_DETECTED.code());
    }

    @Test
    void decrypt_whenCiphertextBodyTampered_returnsTamperingDetectedCode() {
        EncryptionService service = buildNormalService();

        Result<Ciphertext, EncryptionError> enc =
                service.encrypt("phone: +15551234567", BoundedContext.CONSENT);
        assertThat(enc.isSuccess()).isTrue();

        // Flip a byte in the ciphertext body (byte 30, after the 30-byte header)
        byte[] bytes = enc.getValue().orElseThrow().getValue().clone();
        bytes[30] ^= 0xFF;
        Ciphertext tampered = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                service.decrypt(tampered, BoundedContext.CONSENT);

        assertThat(result.isFailure()).isTrue();
        assertThat(result.getError().orElseThrow().getCode())
                .as("Ciphertext body modification must be detected as TAMPERING_DETECTED")
                .isEqualTo(EncryptionErrorCodes.TAMPERING_DETECTED.code());
    }

    @Test
    void decrypt_whenFormatInvalid_returnsFormatErrorNotTamperingDetected() {
        // A format/version error is distinct from a tampering error
        EncryptionService service = buildNormalService();

        byte[] bytes = buildMinimalCiphertextBytes();
        bytes[0] = 0x02; // unsupported version — format error, not tampering
        Ciphertext ciphertext = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                service.decrypt(ciphertext, BoundedContext.PROFILE);

        assertThat(result.isFailure()).isTrue();
        String code = result.getError().orElseThrow().getCode();
        assertThat(code)
                .as("Format/version errors must NOT be reported as TAMPERING_DETECTED")
                .isNotEqualTo(EncryptionErrorCodes.TAMPERING_DETECTED.code());
    }

    @Test
    void decrypt_whenKeyNotFound_returnsKeyErrorNotTamperingDetected() {
        // A missing key is distinct from a tampering error
        EncryptionService service = buildServiceWithKeyNotFoundOnDecrypt();

        byte[] bytes = buildMinimalCiphertextBytes();
        Ciphertext ciphertext = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                service.decrypt(ciphertext, BoundedContext.PROFILE);

        assertThat(result.isFailure()).isTrue();
        String code = result.getError().orElseThrow().getCode();
        assertThat(code)
                .as("Key-not-found errors must NOT be reported as TAMPERING_DETECTED")
                .isNotEqualTo(EncryptionErrorCodes.TAMPERING_DETECTED.code());
    }

    // =========================================================================
    // Error messages must not expose sensitive details
    // =========================================================================

    @ParameterizedTest
    @ValueSource(strings = {
            "user@example.com",
            "+15551234567",
            "John Doe",
            "192.168.1.100",
            "secret-password-123"
    })
    void encrypt_onKeyFailure_errorMessageDoesNotContainPlaintext(String pii) {
        EncryptionService service = buildServiceWithFailingKeyManager();

        Result<Ciphertext, EncryptionError> result =
                service.encrypt(pii, BoundedContext.PROFILE);

        assertThat(result.isFailure()).isTrue();
        EncryptionError error = result.getError().orElseThrow();

        assertThat(error.getMessage())
                .as("Error message must not contain the plaintext PII value")
                .doesNotContain(pii);
        assertThat(error.getCode())
                .as("Error code must not contain the plaintext PII value")
                .doesNotContain(pii);
    }

    @Test
    void decrypt_onTamperingDetected_errorMessageDoesNotContainKeyMaterial() {
        EncryptionService service = buildNormalService();

        Result<Ciphertext, EncryptionError> enc =
                service.encrypt("user@example.com", BoundedContext.PROFILE);
        assertThat(enc.isSuccess()).isTrue();

        byte[] bytes = enc.getValue().orElseThrow().getValue().clone();
        bytes[bytes.length - 1] ^= 0xFF;
        Ciphertext tampered = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                service.decrypt(tampered, BoundedContext.PROFILE);

        assertThat(result.isFailure()).isTrue();
        DecryptionError error = result.getError().orElseThrow();

        // Error message must not contain raw key bytes or plaintext
        assertThat(error.getMessage())
                .as("Tampering error message must not expose key material or plaintext")
                .doesNotContainIgnoringCase("key material")
                .doesNotContainIgnoringCase("user@example.com");
    }

    @Test
    void decrypt_onKeyNotFound_errorMessageDoesNotContainKeyMaterial() {
        EncryptionService service = buildServiceWithKeyNotFoundOnDecrypt();

        byte[] bytes = buildMinimalCiphertextBytes();
        Ciphertext ciphertext = Ciphertext.of(bytes);

        Result<String, DecryptionError> result =
                service.decrypt(ciphertext, BoundedContext.PROFILE);

        assertThat(result.isFailure()).isTrue();
        DecryptionError error = result.getError().orElseThrow();

        // The error message should be a safe generic message, not raw exception details
        assertThat(error.getMessage())
                .as("Key-not-found error message must not expose internal key material")
                .isNotBlank()
                .doesNotContainIgnoringCase("key material");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /** Builds a service backed by a key manager that always fails getActiveDEK. */
    private EncryptionService buildServiceWithFailingKeyManager() {
        IKeyManager failingKeyManager = new FailingKeyManager();
        IAuditLogger noOpLogger = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(failingKeyManager, "test-salt");
        return new EncryptionService(failingKeyManager, blindIndexService, noOpLogger, ivCounter);
    }

    /** Builds a service where getDEK always fails (simulates key not found on decryption). */
    private EncryptionService buildServiceWithKeyNotFoundOnDecrypt() {
        IKeyManager keyManager = new KeyNotFoundOnDecryptKeyManager();
        IAuditLogger noOpLogger = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-salt");
        return new EncryptionService(keyManager, blindIndexService, noOpLogger, ivCounter);
    }

    /** Builds a normal working service. */
    private EncryptionService buildNormalService() {
        UUID dekId = UUID.randomUUID();
        IKeyManager keyManager = new StubKeyManager(dekId);
        IAuditLogger noOpLogger = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-salt");
        return new EncryptionService(keyManager, blindIndexService, noOpLogger, ivCounter);
    }

    /**
     * Builds a syntactically valid 46-byte ciphertext (minimum size) with
     * version=0x01 and algorithm=AES-256-GCM but garbage content.
     */
    private byte[] buildMinimalCiphertextBytes() {
        byte[] bytes = new byte[46];
        bytes[0] = CiphertextFormat.VERSION_1;
        bytes[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;
        return bytes;
    }

    // =========================================================================
    // Test doubles
    // =========================================================================

    /** Key manager that always returns KEY_UNAVAILABLE for getActiveDEK. */
    private static final class FailingKeyManager implements IKeyManager {

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.failure(KeyError.of(
                    EncryptionErrorCodes.KEY_UNAVAILABLE.code(),
                    "KMS is unreachable in test"
            ));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            return Result.failure(KeyError.of(
                    EncryptionErrorCodes.KEY_UNAVAILABLE.code(),
                    "KMS is unreachable in test"
            ));
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
            return Result.failure(KeyError.of(
                    EncryptionErrorCodes.KEY_UNAVAILABLE.code(),
                    "KMS is unreachable in test"
            ));
        }
    }

    /** Key manager where getActiveDEK succeeds but getDEK always returns KEY_NOT_FOUND. */
    private static final class KeyNotFoundOnDecryptKeyManager implements IKeyManager {

        private final UUID keyId = UUID.randomUUID();
        private final DEK dek;

        KeyNotFoundOnDecryptKeyManager() {
            byte[] keyMaterial = new byte[32];
            new SecureRandom().nextBytes(keyMaterial);
            this.dek = DEK.of(keyMaterial);
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.success(DEKWithMetadata.builder()
                    .dek(dek)
                    .keyId(keyId)
                    .kekId(UUID.randomUUID())
                    .context(context)
                    .environment(Environment.DEV)
                    .algorithm(EncryptionAlgorithm.AES_256_GCM)
                    .createdAt(Instant.now())
                    .status(KeyStatus.ACTIVE)
                    .build());
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            return Result.failure(KeyError.of(
                    EncryptionErrorCodes.KEY_NOT_FOUND.code(),
                    "Encryption key not found"
            ));
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

    /** Minimal IKeyManager stub that always returns a fixed DEK. */
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

    /** No-op IAuditLogger that discards all events. */
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

        @Override
        public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent event) {
            return Result.failure(NOOP);
        }
    }
}
