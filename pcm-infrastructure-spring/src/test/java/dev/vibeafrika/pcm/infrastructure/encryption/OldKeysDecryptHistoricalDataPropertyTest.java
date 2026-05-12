package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for DEK rotation: old keys must still decrypt historical data.
 *
 * <p>These tests verify Property 10: Old Keys Decrypt Historical Data — for any data
 * encrypted before a DEK rotation, the data shall still be decryptable after rotation
 * using the old DEK identifier embedded in the ciphertext.
 *
 * <p>Ciphertext format:
 * <pre>
 * Byte 0:      Version (1 byte)
 * Byte 1:      Algorithm ID (1 byte)
 * Bytes 2-17:  Key ID (16 bytes, big-endian UUID)
 * Bytes 18-29: IV (12 bytes)
 * Bytes 30+:   Encrypted data + auth tag (16 bytes)
 * </pre>
 *
 * <p>Validates: THE Key_Manager SHALL maintain previous encryption
 * keys for decrypting existing data.
 */
class OldKeysDecryptHistoricalDataPropertyTest {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Property 10: Old Keys Decrypt Historical Data
     *
     * <p>For any plaintext and bounded context, data encrypted with the old DEK
     * before rotation must still be decryptable after one or more rotations.
     * The ciphertext embeds the old DEK ID, which the KeyManager must retain
     * and serve even after it is no longer the active key.
     */
    @Property(tries = 300)
    @Label("Property 10: Data encrypted before rotation is still decryptable after rotation")
    void dataEncryptedBeforeRotationIsDecryptableAfterRotation(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        // Arrange: build a full KeyManager backed by a stub KMS
        StubKmsClient stubKms = new StubKmsClient();
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        DEKCache dekCache = new DEKCache();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        KeyManager keyManager = new KeyManager(stubKms, noOpAuditLogger, dekCache, Environment.DEV, ivCounter);
        keyManager.initializeBlindIndexKey();

        // Initialize KEK and first DEK
        Result<UUID, KeyError> kekResult = keyManager.initializeKEK(context);
        assertThat(kekResult.isSuccess())
                .as("KEK initialization should succeed for context %s", context)
                .isTrue();

        Result<UUID, KeyError> firstRotateResult = keyManager.rotateDEK(context);
        assertThat(firstRotateResult.isSuccess())
                .as("First DEK rotation should succeed for context %s", context)
                .isTrue();
        UUID oldDEKId = firstRotateResult.getValue().orElseThrow();

        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        EncryptionService encryptionService = new EncryptionService(
                keyManager, blindIndexService, noOpAuditLogger, ivCounter);

        // Encrypt with the old (currently active) DEK — this is the "historical" data
        Result<Ciphertext, EncryptionError> historicalEncryptResult =
                encryptionService.encrypt(plaintext, context);
        assertThat(historicalEncryptResult.isSuccess())
                .as("Encryption before rotation should succeed for plaintext '%s' in context %s",
                        plaintext, context)
                .isTrue();

        Ciphertext historicalCiphertext = historicalEncryptResult.getValue().orElseThrow();

        // Verify the historical ciphertext embeds the old DEK ID
        UUID embeddedOldKeyId = extractKeyIdFromCiphertext(historicalCiphertext.getValue());
        assertThat(embeddedOldKeyId)
                .as("Historical ciphertext must embed the old DEK ID")
                .isEqualTo(oldDEKId);

        // Act: rotate the DEK — old DEK must be retained for decryption
        Result<UUID, KeyError> secondRotateResult = keyManager.rotateDEK(context);
        assertThat(secondRotateResult.isSuccess())
                .as("Second DEK rotation should succeed for context %s", context)
                .isTrue();
        UUID newDEKId = secondRotateResult.getValue().orElseThrow();

        assertThat(newDEKId)
                .as("New DEK ID must differ from old DEK ID after rotation")
                .isNotEqualTo(oldDEKId);

        // Assert: historical ciphertext (encrypted with old DEK) is still decryptable
        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(historicalCiphertext, context);

        assertThat(decryptResult.isSuccess())
                .as("Historical data encrypted with old DEK %s must still be decryptable "
                        + "after rotation to new DEK %s, for plaintext '%s' in context %s",
                        oldDEKId, newDEKId, plaintext, context)
                .isTrue();

        assertThat(decryptResult.getValue().orElseThrow())
                .as("Decrypted historical data must equal the original plaintext")
                .isEqualTo(plaintext);
    }

    /**
     * Property 10 (multiple rotations): Historical data remains decryptable across
     * multiple successive DEK rotations.
     *
     * <p>Encrypts data with the initial DEK, then performs N rotations (2–4), and
     * verifies the original ciphertext is still decryptable after all rotations.
     */
    @Property(tries = 200)
    @Label("Property 10: Historical data remains decryptable across multiple successive rotations")
    void historicalDataRemainsDecryptableAcrossMultipleRotations(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context,
            @ForAll("rotationCount") int rotationCount) {

        StubKmsClient stubKms = new StubKmsClient();
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        DEKCache dekCache = new DEKCache();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        KeyManager keyManager = new KeyManager(stubKms, noOpAuditLogger, dekCache, Environment.DEV, ivCounter);
        keyManager.initializeBlindIndexKey();

        keyManager.initializeKEK(context);

        // Establish the initial DEK
        Result<UUID, KeyError> initialRotate = keyManager.rotateDEK(context);
        assertThat(initialRotate.isSuccess()).isTrue();
        UUID initialDEKId = initialRotate.getValue().orElseThrow();

        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        EncryptionService encryptionService = new EncryptionService(
                keyManager, blindIndexService, noOpAuditLogger, ivCounter);

        // Encrypt historical data with the initial DEK
        Result<Ciphertext, EncryptionError> historicalEncryptResult =
                encryptionService.encrypt(plaintext, context);
        assertThat(historicalEncryptResult.isSuccess())
                .as("Encryption with initial DEK should succeed")
                .isTrue();

        Ciphertext historicalCiphertext = historicalEncryptResult.getValue().orElseThrow();

        // Verify the historical ciphertext embeds the initial DEK ID
        UUID embeddedInitialKeyId = extractKeyIdFromCiphertext(historicalCiphertext.getValue());
        assertThat(embeddedInitialKeyId)
                .as("Historical ciphertext must embed the initial DEK ID")
                .isEqualTo(initialDEKId);

        // Perform N successive rotations
        UUID latestDEKId = initialDEKId;
        for (int i = 0; i < rotationCount; i++) {
            Result<UUID, KeyError> rotateResult = keyManager.rotateDEK(context);
            assertThat(rotateResult.isSuccess())
                    .as("Rotation %d of %d should succeed for context %s", i + 1, rotationCount, context)
                    .isTrue();
            UUID rotatedDEKId = rotateResult.getValue().orElseThrow();
            assertThat(rotatedDEKId)
                    .as("Each rotation must produce a new unique DEK ID")
                    .isNotEqualTo(latestDEKId);
            latestDEKId = rotatedDEKId;
        }

        // Assert: historical ciphertext is still decryptable after all rotations
        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(historicalCiphertext, context);

        assertThat(decryptResult.isSuccess())
                .as("Historical data encrypted with initial DEK %s must still be decryptable "
                        + "after %d rotations (latest DEK: %s), for plaintext '%s' in context %s",
                        initialDEKId, rotationCount, latestDEKId, plaintext, context)
                .isTrue();

        assertThat(decryptResult.getValue().orElseThrow())
                .as("Decrypted historical data must equal the original plaintext after %d rotations",
                        rotationCount)
                .isEqualTo(plaintext);
    }

    /**
     * Property 10 (concurrent historical data): Multiple ciphertexts encrypted with
     * different historical DEKs are all decryptable after further rotations.
     *
     * <p>Encrypts one record per DEK generation, then rotates once more, and verifies
     * all historical records remain decryptable.
     */
    @Property(tries = 150)
    @Label("Property 10: All historical ciphertexts from different DEK generations remain decryptable")
    void allHistoricalCiphertextsFromDifferentDEKGenerationsRemainDecryptable(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        StubKmsClient stubKms = new StubKmsClient();
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        DEKCache dekCache = new DEKCache();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        KeyManager keyManager = new KeyManager(stubKms, noOpAuditLogger, dekCache, Environment.DEV, ivCounter);
        keyManager.initializeBlindIndexKey();

        keyManager.initializeKEK(context);

        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        EncryptionService encryptionService = new EncryptionService(
                keyManager, blindIndexService, noOpAuditLogger, ivCounter);

        // Encrypt one record per DEK generation across 3 rotations
        int generations = 3;
        List<Ciphertext> historicalCiphertexts = new ArrayList<>();
        List<UUID> historicalDEKIds = new ArrayList<>();

        for (int gen = 0; gen < generations; gen++) {
            Result<UUID, KeyError> rotateResult = keyManager.rotateDEK(context);
            assertThat(rotateResult.isSuccess())
                    .as("Rotation for generation %d should succeed", gen)
                    .isTrue();
            UUID dekId = rotateResult.getValue().orElseThrow();
            historicalDEKIds.add(dekId);

            // Encrypt a record with this generation's DEK
            Result<Ciphertext, EncryptionError> encryptResult =
                    encryptionService.encrypt(plaintext, context);
            assertThat(encryptResult.isSuccess())
                    .as("Encryption in generation %d should succeed", gen)
                    .isTrue();

            Ciphertext ciphertext = encryptResult.getValue().orElseThrow();
            historicalCiphertexts.add(ciphertext);

            // Verify the ciphertext embeds the correct DEK ID for this generation
            UUID embeddedKeyId = extractKeyIdFromCiphertext(ciphertext.getValue());
            assertThat(embeddedKeyId)
                    .as("Generation %d ciphertext must embed DEK ID %s", gen, dekId)
                    .isEqualTo(dekId);
        }

        // Perform one final rotation to make all previous DEKs "historical"
        Result<UUID, KeyError> finalRotate = keyManager.rotateDEK(context);
        assertThat(finalRotate.isSuccess()).isTrue();
        UUID finalDEKId = finalRotate.getValue().orElseThrow();

        // Assert: every historical ciphertext from every generation is still decryptable
        for (int gen = 0; gen < generations; gen++) {
            Ciphertext historicalCiphertext = historicalCiphertexts.get(gen);
            UUID historicalDEKId = historicalDEKIds.get(gen);

            Result<String, DecryptionError> decryptResult =
                    encryptionService.decrypt(historicalCiphertext, context);

            assertThat(decryptResult.isSuccess())
                    .as("Generation %d ciphertext (DEK: %s) must be decryptable after final rotation "
                            + "(current DEK: %s), for plaintext '%s' in context %s",
                            gen, historicalDEKId, finalDEKId, plaintext, context)
                    .isTrue();

            assertThat(decryptResult.getValue().orElseThrow())
                    .as("Decrypted generation %d data must equal the original plaintext", gen)
                    .isEqualTo(plaintext);
        }
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
                .ofMinLength(1)
                .ofMaxLength(200);

        return Arbitraries.oneOf(emails, phones, names, general);
    }

    @Provide
    Arbitrary<BoundedContext> boundedContext() {
        return Arbitraries.of(BoundedContext.values());
    }

    /** Number of successive rotations: 2 to 4. */
    @Provide
    Arbitrary<Integer> rotationCount() {
        return Arbitraries.integers().between(2, 4);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Extracts the DEK UUID from bytes 2-17 of the ciphertext (big-endian).
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

    // -------------------------------------------------------------------------
    // Test infrastructure
    // -------------------------------------------------------------------------

    /**
     * A stub IKMSClient that performs real AES-256-GCM DEK wrapping in memory,
     * without any external KMS dependency.
     */
    private static final class StubKmsClient implements IKMSClient {

        private final Map<UUID, byte[]> kekStore = new java.util.concurrent.ConcurrentHashMap<>();

        @Override
        public Result<UUID, KMSError> generateKEK(BoundedContext context, Environment environment) {
            UUID kekId = UUID.randomUUID();
            byte[] kekBytes = new byte[32];
            SECURE_RANDOM.nextBytes(kekBytes);
            kekStore.put(kekId, kekBytes);
            return Result.success(kekId);
        }

        @Override
        public Result<EncryptedDEK, KMSError> encryptDEK(DEK dek, UUID kekId) {
            byte[] kekBytes = kekStore.get(kekId);
            if (kekBytes == null) {
                return Result.failure(KMSError.of("KEK_NOT_FOUND", "KEK not found: " + kekId));
            }
            try {
                javax.crypto.SecretKey kek = new javax.crypto.spec.SecretKeySpec(kekBytes, "AES");
                javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                byte[] iv = new byte[12];
                SECURE_RANDOM.nextBytes(iv);
                cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, kek,
                        new javax.crypto.spec.GCMParameterSpec(128, iv));
                byte[] encryptedDEKBytes = cipher.doFinal(dek.getKeyMaterial());
                byte[] combined = new byte[iv.length + encryptedDEKBytes.length];
                System.arraycopy(iv, 0, combined, 0, iv.length);
                System.arraycopy(encryptedDEKBytes, 0, combined, iv.length, encryptedDEKBytes.length);
                return Result.success(EncryptedDEK.of(combined, kekId));
            } catch (Exception e) {
                return Result.failure(KMSError.of("ENCRYPTION_FAILED", e.getMessage()));
            }
        }

        @Override
        public Result<DEK, KMSError> decryptDEK(EncryptedDEK encryptedDEK, UUID kekId) {
            byte[] kekBytes = kekStore.get(kekId);
            if (kekBytes == null) {
                return Result.failure(KMSError.of("KEK_NOT_FOUND", "KEK not found: " + kekId));
            }
            try {
                byte[] combined = encryptedDEK.getCiphertext();
                byte[] iv = new byte[12];
                System.arraycopy(combined, 0, iv, 0, 12);
                byte[] encryptedDEKBytes = new byte[combined.length - 12];
                System.arraycopy(combined, 12, encryptedDEKBytes, 0, encryptedDEKBytes.length);

                javax.crypto.SecretKey kek = new javax.crypto.spec.SecretKeySpec(kekBytes, "AES");
                javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(javax.crypto.Cipher.DECRYPT_MODE, kek,
                        new javax.crypto.spec.GCMParameterSpec(128, iv));
                byte[] dekBytes = cipher.doFinal(encryptedDEKBytes);
                return Result.success(DEK.of(dekBytes));
            } catch (Exception e) {
                return Result.failure(KMSError.of("DECRYPTION_FAILED", e.getMessage()));
            }
        }

        @Override
        public Result<Unit, KMSError> deleteDEK(UUID keyId) {
            return Result.success(Unit.unit());
        }

        @Override
        public Result<KMSHealth, KMSError> healthCheck() {
            return Result.success(KMSHealth.healthy(0L));
        }

        @Override
        public Result<Unit, KMSError> storeSecret(java.util.UUID secretId, String secretValue, java.util.UUID kekId) {
            return Result.success(Unit.unit());
        }

        @Override
        public Result<String, KMSError> retrieveSecret(java.util.UUID secretId, java.util.UUID kekId) {
            return Result.failure(KMSError.of("NOT_IMPLEMENTED", "retrieveSecret not implemented in stub"));
        }

        @Override
        public Result<Unit, KMSError> deleteSecret(java.util.UUID secretId) {
            return Result.success(Unit.unit());
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
