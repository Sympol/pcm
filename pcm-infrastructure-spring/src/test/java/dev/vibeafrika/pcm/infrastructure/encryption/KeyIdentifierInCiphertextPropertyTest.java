package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for key identifier storage in ciphertext.
 *
 * <p>These tests verify Property 12: Key Identifier in Ciphertext — for any
 * encrypted ciphertext, the ciphertext shall contain the UUID of the DEK used
 * for encryption at bytes 2-17 (big-endian).
 *
 * <p>Ciphertext format:
 * <pre>
 * Byte 0:      Version (1 byte)
 * Byte 1:      Algorithm ID (1 byte)
 * Bytes 2-17:  Key ID (16 bytes, big-endian UUID)  ← verified by this property
 * Bytes 18-29: IV (12 bytes)
 * Bytes 30+:   Encrypted data + auth tag (16 bytes)
 * </pre>
 */
class KeyIdentifierInCiphertextPropertyTest {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Property 12: Key Identifier in Ciphertext
     *
     * <p>For any plaintext string and bounded context, when encrypted, the resulting
     * ciphertext bytes at positions 2-17 (inclusive) must match the UUID of the DEK
     * used for encryption, stored in big-endian format (most significant byte first).
     *
     * <p>This validates:
     * <ul>
     *   <li> The Key_Manager SHALL associate each encrypted value
     *       with a key identifier</li>
     *   <li> When decrypting data, the Encryption_Service SHALL use
     *       the key identifier to select the correct decryption key</li>
     * </ul>
     */
    @Property(tries = 300)
    @Label("Ciphertext bytes 2-17 contain the UUID of the DEK used for encryption (big-endian)")
    void ciphertextContainsDEKUUIDAtBytes2To17(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        // Arrange: a known DEK ID so we can verify it appears in the ciphertext
        UUID expectedDEKId = UUID.randomUUID();
        IKeyManager stubKeyManager = new StubKeyManager(expectedDEKId);
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(stubKeyManager, "test-global-salt");
        EncryptionService encryptionService = new EncryptionService(
                stubKeyManager, blindIndexService, noOpAuditLogger, ivCounter);

        // Act: encrypt the plaintext
        Result<Ciphertext, EncryptionError> result =
                encryptionService.encrypt(plaintext, context);

        assertThat(result.isSuccess())
                .as("Encryption of '%s' in context %s should succeed", plaintext, context)
                .isTrue();

        byte[] ciphertextBytes = result.getValue().orElseThrow().getValue();

        // Assert: ciphertext is long enough to contain the key ID field
        assertThat(ciphertextBytes.length)
                .as("Ciphertext must be at least 18 bytes to contain the key ID field (bytes 2-17)")
                .isGreaterThanOrEqualTo(18);

        // Extract bytes 2-17 and reconstruct the UUID (big-endian)
        UUID embeddedKeyId = extractUUIDFromBytes(ciphertextBytes, 2);

        assertThat(embeddedKeyId)
                .as("Bytes 2-17 of the ciphertext must equal the DEK UUID used for encryption")
                .isEqualTo(expectedDEKId);
    }

    /**
     * Property 12 (big-endian encoding): The UUID is stored in big-endian byte order.
     *
     * <p>Verifies that the most significant byte of the UUID's most significant bits
     * appears at byte 2, and the least significant byte of the UUID's least significant
     * bits appears at byte 17.
     */
    @Property(tries = 200)
    @Label("Key ID UUID is stored in big-endian byte order at bytes 2-17")
    void keyIdIsStoredInBigEndianByteOrder(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        UUID expectedDEKId = UUID.randomUUID();
        IKeyManager stubKeyManager = new StubKeyManager(expectedDEKId);
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(stubKeyManager, "test-global-salt");
        EncryptionService encryptionService = new EncryptionService(
                stubKeyManager, blindIndexService, noOpAuditLogger, ivCounter);

        Result<Ciphertext, EncryptionError> result =
                encryptionService.encrypt(plaintext, context);

        assertThat(result.isSuccess())
                .as("Encryption should succeed")
                .isTrue();

        byte[] ciphertextBytes = result.getValue().orElseThrow().getValue();

        // Verify big-endian encoding: MSB of mostSignificantBits at byte 2
        long msb = expectedDEKId.getMostSignificantBits();
        long lsb = expectedDEKId.getLeastSignificantBits();

        for (int i = 0; i < 8; i++) {
            byte expectedByte = (byte) (msb >>> (56 - 8 * i));
            assertThat(ciphertextBytes[2 + i])
                    .as("Byte %d of ciphertext must equal MSB byte %d of DEK UUID (big-endian)", 2 + i, i)
                    .isEqualTo(expectedByte);
        }

        for (int i = 0; i < 8; i++) {
            byte expectedByte = (byte) (lsb >>> (56 - 8 * i));
            assertThat(ciphertextBytes[10 + i])
                    .as("Byte %d of ciphertext must equal LSB byte %d of DEK UUID (big-endian)", 10 + i, i)
                    .isEqualTo(expectedByte);
        }
    }

    /**
     * Property 12 (key ID enables decryption): The key ID embedded in the ciphertext
     * is sufficient to identify and retrieve the correct DEK for decryption.
     *
     * <p>This validates directly: the Encryption_Service uses the
     * key identifier extracted from the ciphertext to select the correct decryption key.
     */
    @Property(tries = 200)
    @Label("Key ID embedded in ciphertext enables correct DEK selection for decryption")
    void keyIdInCiphertextEnablesCorrectDEKSelectionForDecryption(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        UUID expectedDEKId = UUID.randomUUID();
        IKeyManager stubKeyManager = new StubKeyManager(expectedDEKId);
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(stubKeyManager, "test-global-salt");
        EncryptionService encryptionService = new EncryptionService(
                stubKeyManager, blindIndexService, noOpAuditLogger, ivCounter);

        // Encrypt
        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(plaintext, context);

        assertThat(encryptResult.isSuccess())
                .as("Encryption should succeed")
                .isTrue();

        Ciphertext ciphertext = encryptResult.getValue().orElseThrow();
        byte[] ciphertextBytes = ciphertext.getValue();

        // Extract the key ID from the ciphertext
        UUID embeddedKeyId = extractUUIDFromBytes(ciphertextBytes, 2);

        assertThat(embeddedKeyId)
                .as("Embedded key ID must match the DEK used for encryption")
                .isEqualTo(expectedDEKId);

        // Verify that decryption succeeds (proving the embedded key ID is used correctly)
        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(ciphertext, context);

        assertThat(decryptResult.isSuccess())
                .as("Decryption using the embedded key ID should succeed")
                .isTrue();

        assertThat(decryptResult.getValue().orElseThrow())
                .as("Decrypted value must equal the original plaintext")
                .isEqualTo(plaintext);
    }

    // -------------------------------------------------------------------------
    // Arbitraries
    // -------------------------------------------------------------------------

    @Provide
    Arbitrary<String> piiLikePlaintext() {
        Arbitrary<String> emails = Combinators.combine(
                Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(20),
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(10),
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(5)
        ).as((user, domain, tld) -> user + "@" + domain + "." + tld);

        Arbitrary<String> phones = Arbitraries.integers().between(100000000, 999999999)
                .map(n -> "+1" + n);

        Arbitrary<String> names = Combinators.combine(
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(15),
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(15)
        ).as((first, last) -> first + " " + last);

        Arbitrary<String> general = Arbitraries.strings()
                .withCharRange(' ', '~')
                .ofMinLength(0)
                .ofMaxLength(200);

        return Arbitraries.oneOf(emails, phones, names, general);
    }

    @Provide
    Arbitrary<BoundedContext> boundedContext() {
        return Arbitraries.of(BoundedContext.values());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Extracts a UUID from 16 bytes starting at {@code offset} in big-endian format.
     *
     * <p>Bytes [offset, offset+7] form the most significant bits;
     * bytes [offset+8, offset+15] form the least significant bits.
     */
    private static UUID extractUUIDFromBytes(byte[] bytes, int offset) {
        long msb = 0;
        long lsb = 0;
        for (int i = 0; i < 8; i++) {
            msb = (msb << 8) | (bytes[offset + i] & 0xFF);
        }
        for (int i = 0; i < 8; i++) {
            lsb = (lsb << 8) | (bytes[offset + 8 + i] & 0xFF);
        }
        return new UUID(msb, lsb);
    }

    // -------------------------------------------------------------------------
    // Test infrastructure
    // -------------------------------------------------------------------------

    /**
     * Minimal IKeyManager stub that always returns a fixed DEK with a known key ID.
     */
    private static final class StubKeyManager implements IKeyManager {

        private final UUID keyId;
        private final DEK dek;

        StubKeyManager(UUID keyId) {
            this.keyId = keyId;
            byte[] keyMaterial = new byte[32];
            SECURE_RANDOM.nextBytes(keyMaterial);
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
            SECURE_RANDOM.nextBytes(key);
            return Result.success(key);
        }
    }

    /**
     * No-op IAuditLogger that discards all events.
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

        @Override
        public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent event) {
            return Result.failure(NOOP);
        }
    }
}
