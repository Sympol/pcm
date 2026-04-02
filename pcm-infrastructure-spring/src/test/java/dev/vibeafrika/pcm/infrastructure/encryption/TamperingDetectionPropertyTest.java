package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for tampering detection.
 *
 * <p>These tests verify Property 4: Tampering Detection — modifying any byte in a
 * ciphertext must cause decryption to fail with a tampering error.
 *
 * <p>The ciphertext format is:
 * {@code [version(1)][algorithm_id(1)][key_id(16)][IV(12)][ciphertext(N)][auth_tag(16)]}
 * with a total header overhead of 46 bytes.
 */
class TamperingDetectionPropertyTest {

    /**
     * Property 4: Tampering Detection
     *
     * <p>For any plaintext string and bounded context, encrypting produces a valid ciphertext.
     * Modifying any single byte in that ciphertext must cause decryption to fail with a
     * {@code TAMPERING_DETECTED} error (or at minimum a decryption failure).
     *
     * <p>This covers:
     * <ul>
     *   <li>Modifying auth tag bytes (last 16 bytes)</li>
     *   <li>Modifying ciphertext body bytes</li>
     *   <li>Modifying IV bytes (bytes 18–29)</li>
     * </ul>
     */
    @Property(tries = 200)
    @Label("Modifying any byte in ciphertext causes decryption to fail")
    void modifyingAnyByteInCiphertextCausesDecryptionFailure(
            @ForAll("plaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService encryptionService = buildEncryptionService();

        // Encrypt to get a valid ciphertext
        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(plaintext, context);

        assertThat(encryptResult.isSuccess())
                .as("Encryption of '%s' in context %s should succeed", plaintext, context)
                .isTrue();

        byte[] originalBytes = encryptResult.getValue().orElseThrow().getValue();
        int ciphertextLength = originalBytes.length;

        // Test tampering at every byte position
        for (int bytePos = 0; bytePos < ciphertextLength; bytePos++) {
            byte[] tampered = originalBytes.clone();
            // Flip all bits in the target byte to guarantee a change
            tampered[bytePos] = (byte) ~tampered[bytePos];

            Ciphertext tamperedCiphertext;
            try {
                tamperedCiphertext = Ciphertext.of(tampered);
            } catch (IllegalArgumentException e) {
                // If the tampered bytes are too short (shouldn't happen here), skip
                continue;
            }

            Result<String, DecryptionError> decryptResult =
                    encryptionService.decrypt(tamperedCiphertext, context);

            assertThat(decryptResult.isSuccess())
                    .as("Decryption of ciphertext tampered at byte %d (length=%d) should fail",
                            bytePos, ciphertextLength)
                    .isFalse();
        }
    }

    /**
     * Property 4 (auth tag): Modifying the authentication tag bytes returns TAMPERING_DETECTED.
     *
     * <p>The auth tag occupies the last 16 bytes of the ciphertext. Any modification
     * must be detected by AES-256-GCM and reported as {@code TAMPERING_DETECTED}.
     */
    @Property(tries = 200)
    @Label("Modifying auth tag bytes returns TAMPERING_DETECTED error code")
    void modifyingAuthTagReturnsTamperingDetectedError(
            @ForAll("plaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context,
            @ForAll("authTagByteOffset") int authTagOffset) {

        EncryptionService encryptionService = buildEncryptionService();

        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(plaintext, context);

        assertThat(encryptResult.isSuccess())
                .as("Encryption should succeed")
                .isTrue();

        byte[] originalBytes = encryptResult.getValue().orElseThrow().getValue();
        int ciphertextLength = originalBytes.length;

        // Auth tag is the last 16 bytes
        int authTagStart = ciphertextLength - 16;
        int targetByte = authTagStart + (authTagOffset % 16);

        byte[] tampered = originalBytes.clone();
        tampered[targetByte] = (byte) ~tampered[targetByte];

        Ciphertext tamperedCiphertext = Ciphertext.of(tampered);

        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(tamperedCiphertext, context);

        assertThat(decryptResult.isSuccess())
                .as("Decryption with tampered auth tag at offset %d should fail", authTagOffset)
                .isFalse();

        DecryptionError error = decryptResult.getError().orElseThrow();
        assertThat(error.getCode())
                .as("Error code for tampered auth tag must be TAMPERING_DETECTED")
                .isEqualTo("TAMPERING_DETECTED");
    }

    /**
     * Property 4 (IV bytes): Modifying IV bytes causes decryption to fail.
     *
     * <p>The IV occupies bytes 18–29 (12 bytes). Modifying any IV byte changes the
     * decryption context, causing the authentication tag verification to fail.
     */
    @Property(tries = 200)
    @Label("Modifying IV bytes causes decryption to fail")
    void modifyingIVBytesFailsDecryption(
            @ForAll("nonEmptyPlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context,
            @ForAll("ivByteOffset") int ivOffset) {

        EncryptionService encryptionService = buildEncryptionService();

        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(plaintext, context);

        assertThat(encryptResult.isSuccess())
                .as("Encryption should succeed")
                .isTrue();

        byte[] originalBytes = encryptResult.getValue().orElseThrow().getValue();

        // IV is at bytes 18–29 (after version(1) + algorithm_id(1) + key_id(16))
        int ivStart = 18;
        int targetByte = ivStart + (ivOffset % 12);

        byte[] tampered = originalBytes.clone();
        tampered[targetByte] = (byte) ~tampered[targetByte];

        Ciphertext tamperedCiphertext = Ciphertext.of(tampered);

        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(tamperedCiphertext, context);

        assertThat(decryptResult.isSuccess())
                .as("Decryption with tampered IV at offset %d should fail", ivOffset)
                .isFalse();
    }

    /**
     * Property 4 (ciphertext body): Modifying ciphertext body bytes causes decryption to fail.
     *
     * <p>The ciphertext body starts at byte 30 (after the 30-byte header) and ends
     * before the last 16 auth tag bytes. Any modification must be detected.
     */
    @Property(tries = 200)
    @Label("Modifying ciphertext body bytes causes decryption to fail")
    void modifyingCiphertextBodyFailsDecryption(
            @ForAll("nonEmptyPlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService encryptionService = buildEncryptionService();

        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(plaintext, context);

        assertThat(encryptResult.isSuccess())
                .as("Encryption should succeed")
                .isTrue();

        byte[] originalBytes = encryptResult.getValue().orElseThrow().getValue();
        int ciphertextLength = originalBytes.length;

        // Ciphertext body: bytes 30 to (length - 16 - 1)
        // Header: version(1) + algorithm_id(1) + key_id(16) + IV(12) = 30 bytes
        int bodyStart = 30;
        int bodyEnd = ciphertextLength - 16; // exclusive, auth tag starts here

        // Only test if there is a body (non-empty plaintext produces at least 1 body byte)
        if (bodyEnd <= bodyStart) {
            return;
        }

        // Flip the first byte of the ciphertext body
        byte[] tampered = originalBytes.clone();
        tampered[bodyStart] = (byte) ~tampered[bodyStart];

        Ciphertext tamperedCiphertext = Ciphertext.of(tampered);

        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(tamperedCiphertext, context);

        assertThat(decryptResult.isSuccess())
                .as("Decryption with tampered ciphertext body should fail")
                .isFalse();
    }

    // -------------------------------------------------------------------------
    // Arbitraries
    // -------------------------------------------------------------------------

    @Provide
    Arbitrary<String> plaintext() {
        return Arbitraries.strings()
                .withCharRange(' ', '~')
                .ofMinLength(0)
                .ofMaxLength(200);
    }

    @Provide
    Arbitrary<String> nonEmptyPlaintext() {
        return Arbitraries.strings()
                .withCharRange(' ', '~')
                .ofMinLength(1)
                .ofMaxLength(200);
    }

    @Provide
    Arbitrary<BoundedContext> boundedContext() {
        return Arbitraries.of(BoundedContext.values());
    }

    /** Offset within the 16-byte auth tag (0–15). */
    @Provide
    Arbitrary<Integer> authTagByteOffset() {
        return Arbitraries.integers().between(0, 15);
    }

    /** Offset within the 12-byte IV (0–11). */
    @Provide
    Arbitrary<Integer> ivByteOffset() {
        return Arbitraries.integers().between(0, 11);
    }

    // -------------------------------------------------------------------------
    // Test infrastructure
    // -------------------------------------------------------------------------

    /**
     * Builds a self-contained EncryptionService with in-memory stubs.
     * Each call creates a fresh service with a new DEK so tests are independent.
     */
    private EncryptionService buildEncryptionService() {
        UUID dekId = UUID.randomUUID();
        IKeyManager stubKeyManager = new StubKeyManager(dekId);
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(stubKeyManager, "test-global-salt");
        return new EncryptionService(stubKeyManager, blindIndexService, noOpAuditLogger, ivCounter);
    }

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
