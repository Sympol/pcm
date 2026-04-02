package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for multiple active encryption keys support.
 *
 * <p>These tests verify Property 8: Multiple Active Keys Support — for any set of
 * active DEKs, data encrypted with any DEK shall be decryptable using the correct
 * DEK identifier extracted from the ciphertext.
 */
class MultipleActiveKeysPropertyTest {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Property 8: Multiple Active Keys Support
     *
     * <p>For any set of active DEKs (2–5 keys) and any plaintext, encrypting with
     * any one of those DEKs and then decrypting using the key ID embedded in the
     * ciphertext must produce the original plaintext.
     *
     * <p>This validates that:
     * <ul>
     *   <li>The Key_Manager supports multiple active DEKs simultaneously</li>
     *   <li>The ciphertext embeds the correct DEK identifier (bytes 2–17)</li>
     *   <li>Decryption retrieves the exact DEK that was used for encryption</li>
     *   <li>Data encrypted with any DEK in the active set is fully recoverable</li>
     * </ul>
     */
    @Property(tries = 300)
    @Label("Data encrypted with any active DEK is decryptable using the correct DEK identifier")
    void dataEncryptedWithAnyActiveDEKIsDecryptableUsingCorrectDEKIdentifier(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context,
            @ForAll("dekCount") int dekCount) {

        // Build a key manager with multiple active DEKs
        MultiDEKKeyManager multiDEKKeyManager = new MultiDEKKeyManager(dekCount, context);
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(multiDEKKeyManager, "test-global-salt");
        EncryptionService encryptionService = new EncryptionService(
                multiDEKKeyManager, blindIndexService, noOpAuditLogger, ivCounter);

        // Encrypt using each DEK in the active set
        for (UUID dekId : multiDEKKeyManager.getAllDEKIds()) {
            // Set the active DEK to this specific key
            multiDEKKeyManager.setActiveDEK(dekId);

            // Encrypt the plaintext with the current active DEK
            Result<Ciphertext, EncryptionError> encryptResult =
                    encryptionService.encrypt(plaintext, context);

            assertThat(encryptResult.isSuccess())
                    .as("Encryption with DEK %s should succeed for plaintext '%s' in context %s",
                            dekId, plaintext, context)
                    .isTrue();

            Ciphertext ciphertext = encryptResult.getValue().orElseThrow();

            // Verify the ciphertext embeds the correct DEK identifier (bytes 2–17)
            byte[] ciphertextBytes = ciphertext.getValue();
            assertThat(ciphertextBytes.length)
                    .as("Ciphertext must be at least 18 bytes to contain the key ID field")
                    .isGreaterThanOrEqualTo(18);

            UUID embeddedKeyId = extractKeyIdFromCiphertext(ciphertextBytes);
            assertThat(embeddedKeyId)
                    .as("Ciphertext must embed the DEK ID used for encryption")
                    .isEqualTo(dekId);

            // Decrypt using the key ID embedded in the ciphertext (simulates real decryption flow)
            Result<String, DecryptionError> decryptResult =
                    encryptionService.decrypt(ciphertext, context);

            assertThat(decryptResult.isSuccess())
                    .as("Decryption using embedded DEK ID %s should succeed for plaintext '%s'",
                            dekId, plaintext)
                    .isTrue();

            assertThat(decryptResult.getValue().orElseThrow())
                    .as("Decrypted value must equal the original plaintext when using DEK %s", dekId)
                    .isEqualTo(plaintext);
        }
    }

    /**
     * Property 8 (cross-key isolation): Data encrypted with one DEK cannot be
     * decrypted with a different DEK from the same active set.
     *
     * <p>This verifies that each DEK is truly independent — using the wrong key
     * must fail, even when both keys are in the active set.
     */
    @Property(tries = 200)
    @Label("Data encrypted with one DEK cannot be decrypted with a different DEK")
    void dataEncryptedWithOneDEKCannotBeDecryptedWithDifferentDEK(
            @ForAll("nonEmptyPlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        // Build a key manager with exactly 2 DEKs
        MultiDEKKeyManager multiDEKKeyManager = new MultiDEKKeyManager(2, context);
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(multiDEKKeyManager, "test-global-salt");
        EncryptionService encryptionService = new EncryptionService(
                multiDEKKeyManager, blindIndexService, noOpAuditLogger, ivCounter);

        List<UUID> dekIds = new ArrayList<>(multiDEKKeyManager.getAllDEKIds());
        UUID firstDEKId = dekIds.get(0);
        UUID secondDEKId = dekIds.get(1);

        // Encrypt with the first DEK
        multiDEKKeyManager.setActiveDEK(firstDEKId);
        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(plaintext, context);

        assertThat(encryptResult.isSuccess())
                .as("Encryption with first DEK should succeed")
                .isTrue();

        Ciphertext ciphertext = encryptResult.getValue().orElseThrow();

        // Tamper: replace the key ID in the ciphertext with the second DEK's ID
        byte[] tamperedBytes = ciphertext.getValue().clone();
        writeUUIDToBytes(secondDEKId, tamperedBytes, 2);
        Ciphertext tamperedCiphertext = Ciphertext.of(tamperedBytes);

        // Decryption with the wrong DEK must fail
        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(tamperedCiphertext, context);

        assertThat(decryptResult.isSuccess())
                .as("Decryption with wrong DEK ID must fail (AES-GCM auth tag will not match)")
                .isFalse();
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

    /** Number of active DEKs in the set: 2 to 5. */
    @Provide
    Arbitrary<Integer> dekCount() {
        return Arbitraries.integers().between(2, 5);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Extracts the DEK UUID from bytes 2–17 of the ciphertext (big-endian).
     *
     * <p>Ciphertext format: [version(1)][algorithm_id(1)][key_id(16)][IV(12)][ct(N)][tag(16)]
     */
    private static UUID extractKeyIdFromCiphertext(byte[] ciphertextBytes) {
        long msb = 0;
        long lsb = 0;
        for (int i = 2; i < 10; i++) {
            msb = (msb << 8) | (ciphertextBytes[i] & 0xFF);
        }
        for (int i = 10; i < 18; i++) {
            lsb = (lsb << 8) | (ciphertextBytes[i] & 0xFF);
        }
        return new UUID(msb, lsb);
    }

    /**
     * Writes a UUID into a byte array at the given offset in big-endian format.
     */
    private static void writeUUIDToBytes(UUID uuid, byte[] bytes, int offset) {
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) {
            bytes[offset + i] = (byte) (msb >>> (56 - 8 * i));
        }
        for (int i = 0; i < 8; i++) {
            bytes[offset + 8 + i] = (byte) (lsb >>> (56 - 8 * i));
        }
    }

    // -------------------------------------------------------------------------
    // Test infrastructure
    // -------------------------------------------------------------------------

    /**
     * A stub IKeyManager that holds multiple active DEKs simultaneously.
     *
     * <p>Supports:
     * <ul>
     *   <li>{@link #setActiveDEK(UUID)} — selects which DEK is returned by {@code getActiveDEK}</li>
     *   <li>{@link #getDEK(UUID)} — returns the exact DEK for the given key ID</li>
     *   <li>{@link #getAllDEKIds()} — returns all DEK IDs in the active set</li>
     * </ul>
     */
    private static final class MultiDEKKeyManager implements IKeyManager {

        private final Map<UUID, DEKWithMetadata> dekMap;
        private volatile UUID activeDEKId;
        private final BoundedContext context;

        MultiDEKKeyManager(int dekCount, BoundedContext context) {
            this.context = context;
            this.dekMap = new LinkedHashMap<>();

            for (int i = 0; i < dekCount; i++) {
                UUID keyId = UUID.randomUUID();
                byte[] keyMaterial = new byte[32];
                SECURE_RANDOM.nextBytes(keyMaterial);
                DEK dek = DEK.of(keyMaterial);

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

                dekMap.put(keyId, metadata);
            }

            // Default active DEK is the first one
            this.activeDEKId = dekMap.keySet().iterator().next();
        }

        /** Sets which DEK is returned by {@code getActiveDEK}. */
        void setActiveDEK(UUID dekId) {
            if (!dekMap.containsKey(dekId)) {
                throw new IllegalArgumentException("Unknown DEK ID: " + dekId);
            }
            this.activeDEKId = dekId;
        }

        /** Returns all DEK IDs in the active set. */
        Set<UUID> getAllDEKIds() {
            return Collections.unmodifiableSet(dekMap.keySet());
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.success(dekMap.get(activeDEKId));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            DEKWithMetadata metadata = dekMap.get(keyId);
            if (metadata == null) {
                return Result.failure(KeyError.of("KEY_NOT_FOUND",
                        "DEK not found for key ID: " + keyId));
            }
            return Result.success(metadata);
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
    }
}
