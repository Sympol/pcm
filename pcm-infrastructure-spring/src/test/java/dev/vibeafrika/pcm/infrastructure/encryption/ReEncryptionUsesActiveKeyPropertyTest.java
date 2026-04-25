package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for re-encryption: updated data must use the current active DEK.
 *
 * <p>These tests verify Property 11: Re-encryption Uses Active Key — for any data
 * update operation after key rotation, the updated data shall be encrypted with the
 * current active DEK (not the old one).
 *
 * <p>Validates: WHEN data is updated, THE Encryption_Service SHALL
 * re-encrypt it with the current active key.
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
class ReEncryptionUsesActiveKeyPropertyTest {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Property 11: Re-encryption Uses Active Key
     *
     * <p>For any plaintext and bounded context, after a DEK rotation, re-encrypting
     * (simulating a data update) must produce a ciphertext whose embedded key_id
     * (bytes 2-17) matches the NEW active DEK — not the old one.
     */
    @Property(tries = 300)
    @Label("Property 11: Re-encrypted data uses the current active DEK after rotation")
    void reEncryptedDataUsesActiveKeyAfterRotation(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        // Arrange: build infrastructure backed by a stub KMS
        StubKmsClient stubKms = new StubKmsClient();
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        DEKCache dekCache = new DEKCache();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        KeyManager keyManager = new KeyManager(stubKms, noOpAuditLogger, dekCache, Environment.DEV, ivCounter);
        keyManager.initializeBlindIndexKey();

        // Initialize KEK for the context
        Result<UUID, KeyError> kekResult = keyManager.initializeKEK(context);
        assertThat(kekResult.isSuccess())
                .as("KEK initialization should succeed for context %s", context)
                .isTrue();

        // Create the initial DEK
        Result<UUID, KeyError> firstRotateResult = keyManager.rotateDEK(context);
        assertThat(firstRotateResult.isSuccess())
                .as("First DEK rotation should succeed for context %s", context)
                .isTrue();
        UUID oldDEKId = firstRotateResult.getValue().orElseThrow();

        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        EncryptionService encryptionService = new EncryptionService(
                keyManager, blindIndexService, noOpAuditLogger, ivCounter);

        // Encrypt the original data with the old (currently active) DEK
        Result<Ciphertext, EncryptionError> originalEncryptResult =
                encryptionService.encrypt(plaintext, context);
        assertThat(originalEncryptResult.isSuccess())
                .as("Original encryption should succeed for plaintext '%s' in context %s",
                        plaintext, context)
                .isTrue();

        Ciphertext originalCiphertext = originalEncryptResult.getValue().orElseThrow();
        UUID originalKeyId = extractKeyIdFromCiphertext(originalCiphertext.getValue());
        assertThat(originalKeyId)
                .as("Original ciphertext must embed the old DEK ID")
                .isEqualTo(oldDEKId);

        // Act: rotate the DEK — simulating a key rotation event
        Result<UUID, KeyError> secondRotateResult = keyManager.rotateDEK(context);
        assertThat(secondRotateResult.isSuccess())
                .as("Second DEK rotation should succeed for context %s", context)
                .isTrue();
        UUID newDEKId = secondRotateResult.getValue().orElseThrow();

        assertThat(newDEKId)
                .as("New DEK ID must differ from old DEK ID after rotation")
                .isNotEqualTo(oldDEKId);

        // Simulate a data update: decrypt the old ciphertext, then re-encrypt
        // (this is what the application does when updating a PII field)
        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(originalCiphertext, context);
        assertThat(decryptResult.isSuccess())
                .as("Decryption of original ciphertext should succeed before re-encryption")
                .isTrue();

        String decryptedPlaintext = decryptResult.getValue().orElseThrow();
        assertThat(decryptedPlaintext)
                .as("Decrypted plaintext must equal the original")
                .isEqualTo(plaintext);

        // Re-encrypt (the "update" operation) — must use the NEW active DEK
        Result<Ciphertext, EncryptionError> reEncryptResult =
                encryptionService.encrypt(decryptedPlaintext, context);
        assertThat(reEncryptResult.isSuccess())
                .as("Re-encryption after rotation should succeed for plaintext '%s' in context %s",
                        plaintext, context)
                .isTrue();

        byte[] reEncryptedBytes = reEncryptResult.getValue().orElseThrow().getValue();
        assertThat(reEncryptedBytes.length)
                .as("Re-encrypted ciphertext must be at least 18 bytes to contain the key ID field")
                .isGreaterThanOrEqualTo(18);

        // Assert: re-encrypted ciphertext embeds the NEW active DEK ID
        UUID reEncryptedKeyId = extractKeyIdFromCiphertext(reEncryptedBytes);

        assertThat(reEncryptedKeyId)
                .as("Re-encrypted ciphertext key_id (bytes 2-17) must equal the new active DEK ID %s, "
                        + "not the old DEK ID %s", newDEKId, oldDEKId)
                .isEqualTo(newDEKId);

        assertThat(reEncryptedKeyId)
                .as("Re-encrypted ciphertext must NOT use the old DEK ID %s", oldDEKId)
                .isNotEqualTo(oldDEKId);

        // Assert: re-encrypted data is still decryptable and yields the original plaintext
        Result<String, DecryptionError> finalDecryptResult =
                encryptionService.decrypt(reEncryptResult.getValue().orElseThrow(), context);
        assertThat(finalDecryptResult.isSuccess())
                .as("Re-encrypted ciphertext must be decryptable")
                .isTrue();

        assertThat(finalDecryptResult.getValue().orElseThrow())
                .as("Decrypted re-encrypted data must equal the original plaintext")
                .isEqualTo(plaintext);
    }

    /**
     * Property 11 (multiple rotations): Re-encryption always uses the latest active DEK,
     * regardless of how many rotations have occurred.
     */
    @Property(tries = 200)
    @Label("Property 11: Re-encryption always uses the latest active DEK across multiple rotations")
    void reEncryptionAlwaysUsesLatestActiveDEKAcrossMultipleRotations(
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

        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        EncryptionService encryptionService = new EncryptionService(
                keyManager, blindIndexService, noOpAuditLogger, ivCounter);

        // Encrypt the original data
        Result<Ciphertext, EncryptionError> originalEncryptResult =
                encryptionService.encrypt(plaintext, context);
        assertThat(originalEncryptResult.isSuccess()).isTrue();

        // Perform N successive rotations
        UUID latestDEKId = initialRotate.getValue().orElseThrow();
        for (int i = 0; i < rotationCount; i++) {
            Result<UUID, KeyError> rotateResult = keyManager.rotateDEK(context);
            assertThat(rotateResult.isSuccess())
                    .as("Rotation %d of %d should succeed", i + 1, rotationCount)
                    .isTrue();
            latestDEKId = rotateResult.getValue().orElseThrow();
        }

        // Simulate data update: decrypt old ciphertext, re-encrypt with current active DEK
        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(originalEncryptResult.getValue().orElseThrow(), context);
        assertThat(decryptResult.isSuccess())
                .as("Decryption of original ciphertext should succeed after %d rotations", rotationCount)
                .isTrue();

        Result<Ciphertext, EncryptionError> reEncryptResult =
                encryptionService.encrypt(decryptResult.getValue().orElseThrow(), context);
        assertThat(reEncryptResult.isSuccess())
                .as("Re-encryption after %d rotations should succeed", rotationCount)
                .isTrue();

        // Assert: re-encrypted ciphertext uses the latest active DEK
        UUID reEncryptedKeyId = extractKeyIdFromCiphertext(
                reEncryptResult.getValue().orElseThrow().getValue());

        assertThat(reEncryptedKeyId)
                .as("After %d rotations, re-encrypted ciphertext must use the latest DEK ID %s",
                        rotationCount, latestDEKId)
                .isEqualTo(latestDEKId);

        // Assert: re-encrypted data is still decryptable
        Result<String, DecryptionError> finalDecryptResult =
                encryptionService.decrypt(reEncryptResult.getValue().orElseThrow(), context);
        assertThat(finalDecryptResult.isSuccess())
                .as("Re-encrypted ciphertext must be decryptable after %d rotations", rotationCount)
                .isTrue();

        assertThat(finalDecryptResult.getValue().orElseThrow())
                .as("Decrypted re-encrypted data must equal the original plaintext after %d rotations",
                        rotationCount)
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

        private final Map<UUID, byte[]> kekStore = new ConcurrentHashMap<>();

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
