package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for IV storage in ciphertext.
 *
 * <p>These tests verify Property 6: IV Storage in Ciphertext — for any encryption
 * operation, the generated IV shall be stored in the ciphertext format at the
 * correct position (bytes 18-29).
 */
class IVStoragePropertyTest {

    /**
     *
     * Property 6: IV Storage in Ciphertext
     *
     * For any plaintext string, the IV generated during encryption must be stored
     * at bytes 18-29 (inclusive) of the resulting ciphertext byte array.
     *
     * <p>Ciphertext format:
     * <pre>
     * Byte 0:     Version (1 byte)
     * Byte 1:     Algorithm ID (1 byte)
     * Bytes 2-17: Key ID (16 bytes)
     * Bytes 18-29: IV (12 bytes)  ← verified by this property
     * Bytes 30+:  Encrypted data + auth tag
     * </pre>
     */
    @Property(tries = 200)
    @Label("Generated IV is stored at bytes 18-29 in the ciphertext")
    void generatedIVIsStoredAtCorrectPositionInCiphertext(
            @ForAll("nonNullPlaintext") String plaintext) {

        // Arrange: a recording IVCounter that captures the last generated IV
        RecordingIVCounter recordingIVCounter = new RecordingIVCounter(
                new IVCounterImpl(new InMemoryIVCounterStorage()));

        UUID dekId = UUID.randomUUID();
        IKeyManager stubKeyManager = new StubKeyManager(dekId);
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();

        EncryptionService encryptionService = new EncryptionService(
                stubKeyManager, new BlindIndexService(stubKeyManager, "test-global-salt"), noOpAuditLogger, recordingIVCounter);

        // Act: encrypt the plaintext
        Result<Ciphertext, EncryptionError> result =
                encryptionService.encrypt(plaintext, BoundedContext.PROFILE);

        // Assert: encryption succeeded
        assertThat(result.isSuccess())
                .as("Encryption of '%s' should succeed", plaintext)
                .isTrue();

        byte[] ciphertextBytes = result.getValue().orElseThrow().getValue();
        IV capturedIV = recordingIVCounter.getLastGeneratedIV();

        assertThat(capturedIV)
                .as("An IV must have been generated during encryption")
                .isNotNull();

        // Extract bytes 18-29 from the ciphertext
        assertThat(ciphertextBytes.length)
                .as("Ciphertext must be at least 30 bytes to contain the IV field")
                .isGreaterThanOrEqualTo(30);

        byte[] ivFromCiphertext = new byte[12];
        System.arraycopy(ciphertextBytes, 18, ivFromCiphertext, 0, 12);

        // Verify the extracted bytes match the captured IV
        assertThat(ivFromCiphertext)
                .as("Bytes 18-29 of the ciphertext must equal the IV generated during encryption")
                .isEqualTo(capturedIV.getValue());
    }

    // -------------------------------------------------------------------------
    // Arbitraries
    // -------------------------------------------------------------------------

    @Provide
    Arbitrary<String> nonNullPlaintext() {
        return Arbitraries.strings()
                .withCharRange(' ', '~')  // printable ASCII
                .ofMinLength(0)
                .ofMaxLength(500);
    }

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    /**
     * Wraps an IVCounter and records the most recently generated IV so the test
     * can compare it against the bytes stored in the ciphertext.
     */
    private static final class RecordingIVCounter implements IVCounter {

        private final IVCounter delegate;
        private volatile IV lastGeneratedIV;

        RecordingIVCounter(IVCounter delegate) {
            this.delegate = delegate;
        }

        @Override
        public Result<IV, IVCounterError> generateIV(UUID dekId) {
            Result<IV, IVCounterError> result = delegate.generateIV(dekId);
            if (result.isSuccess()) {
                lastGeneratedIV = result.getValue().orElseThrow();
            }
            return result;
        }

        @Override
        public Result<Unit, IVCounterError> persistState(UUID dekId) {
            return delegate.persistState(dekId);
        }

        @Override
        public Result<IVCounterState, IVCounterError> loadState(UUID dekId) {
            return delegate.loadState(dekId);
        }

        @Override
        public Result<Unit, IVCounterError> resetState(UUID dekId) {
            return delegate.resetState(dekId);
        }

        IV getLastGeneratedIV() {
            return lastGeneratedIV;
        }
    }

    /**
     * Minimal IKeyManager stub that always returns a fixed DEK for any context.
     */
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
            DEKWithMetadata metadata = DEKWithMetadata.builder()
                    .dek(dek)
                    .keyId(keyId)
                    .kekId(UUID.randomUUID())
                    .context(context)
                    .environment(Environment.DEV)
                    .algorithm(EncryptionAlgorithm.AES_256_GCM)
                    .createdAt(Instant.now())
                    .status(KeyStatus.ACTIVE)
                    .build();
            return Result.success(metadata);
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            return getActiveDEK(BoundedContext.PROFILE);
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

    /**
     * No-op IAuditLogger that discards all events.
     * Returns a failure result (EncryptionService does not check the audit logger return value).
     */
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
