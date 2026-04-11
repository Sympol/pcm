package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for DEK rotation: new key becomes active after rotation.
 *
 * <p>These tests verify Property 9: New Key Becomes Active After Rotation — for any
 * key rotation operation, subsequent encryption operations shall use the newly
 * generated DEK (not the old one).
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
class NewKeyBecomesActivePropertyTest {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Property 9: New Key Becomes Active After Rotation
     *
     * <p>For any plaintext and bounded context, after calling {@code rotateDEK(context)},
     * the next encryption operation must use the new DEK — verified by extracting the
     * key_id from bytes 2-17 of the ciphertext and comparing it to the UUID returned
     * by {@code rotateDEK}.
     */
    @Property(tries = 300)
    @Label("Property 9: After rotateDEK, encryption uses the new DEK (key_id at bytes 2-17 matches new DEK ID)")
    void afterRotationEncryptionUsesNewDEK(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        // Arrange: build a KeyManager backed by a stub KMS
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

        // Create the initial DEK via first rotation
        Result<UUID, KeyError> firstRotateResult = keyManager.rotateDEK(context);
        assertThat(firstRotateResult.isSuccess())
                .as("First DEK rotation should succeed for context %s", context)
                .isTrue();
        UUID oldDEKId = firstRotateResult.getValue().orElseThrow();

        // Verify encryption before second rotation uses the old DEK
        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        EncryptionService encryptionService = new EncryptionService(
                keyManager, blindIndexService, noOpAuditLogger, ivCounter);

        Result<Ciphertext, EncryptionError> beforeRotationResult =
                encryptionService.encrypt(plaintext, context);
        assertThat(beforeRotationResult.isSuccess())
                .as("Encryption before rotation should succeed")
                .isTrue();

        UUID keyIdBeforeRotation = extractKeyIdFromCiphertext(
                beforeRotationResult.getValue().orElseThrow().getValue());
        assertThat(keyIdBeforeRotation)
                .as("Before rotation, ciphertext should embed the old DEK ID")
                .isEqualTo(oldDEKId);

        // Act: rotate the DEK
        Result<UUID, KeyError> secondRotateResult = keyManager.rotateDEK(context);
        assertThat(secondRotateResult.isSuccess())
                .as("Second DEK rotation should succeed for context %s", context)
                .isTrue();
        UUID newDEKId = secondRotateResult.getValue().orElseThrow();

        // The new DEK must be different from the old one
        assertThat(newDEKId)
                .as("New DEK ID must differ from old DEK ID after rotation")
                .isNotEqualTo(oldDEKId);

        // Assert: encryption after rotation uses the new DEK
        Result<Ciphertext, EncryptionError> afterRotationResult =
                encryptionService.encrypt(plaintext, context);
        assertThat(afterRotationResult.isSuccess())
                .as("Encryption after rotation should succeed for plaintext '%s' in context %s",
                        plaintext, context)
                .isTrue();

        byte[] ciphertextBytes = afterRotationResult.getValue().orElseThrow().getValue();
        assertThat(ciphertextBytes.length)
                .as("Ciphertext must be at least 18 bytes to contain the key ID field")
                .isGreaterThanOrEqualTo(18);

        UUID embeddedKeyId = extractKeyIdFromCiphertext(ciphertextBytes);

        assertThat(embeddedKeyId)
                .as("After rotation, ciphertext key_id (bytes 2-17) must equal the new DEK ID %s, "
                        + "not the old DEK ID %s", newDEKId, oldDEKId)
                .isEqualTo(newDEKId);

        assertThat(embeddedKeyId)
                .as("After rotation, ciphertext must NOT use the old DEK ID")
                .isNotEqualTo(oldDEKId);
    }

    /**
     * Property 9 (getActiveDEK reflects new key): After rotation, {@code getActiveDEK}
     * returns the new DEK, not the old one.
     */
    @Property(tries = 200)
    @Label("Property 9: After rotateDEK, getActiveDEK returns the new DEK ID")
    void afterRotationGetActiveDEKReturnsNewDEK(
            @ForAll("boundedContext") BoundedContext context) {

        StubKmsClient stubKms = new StubKmsClient();
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        DEKCache dekCache = new DEKCache();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        KeyManager keyManager = new KeyManager(stubKms, noOpAuditLogger, dekCache, Environment.DEV, ivCounter);
        keyManager.initializeBlindIndexKey();

        // Initialize KEK and first DEK
        keyManager.initializeKEK(context);
        Result<UUID, KeyError> firstRotate = keyManager.rotateDEK(context);
        assertThat(firstRotate.isSuccess()).isTrue();
        UUID oldDEKId = firstRotate.getValue().orElseThrow();

        // Verify getActiveDEK returns the old DEK before rotation
        Result<DEKWithMetadata, KeyError> activeBefore = keyManager.getActiveDEK(context);
        assertThat(activeBefore.isSuccess()).isTrue();
        assertThat(activeBefore.getValue().orElseThrow().getKeyId())
                .as("Before second rotation, active DEK should be the first DEK")
                .isEqualTo(oldDEKId);

        // Rotate
        Result<UUID, KeyError> secondRotate = keyManager.rotateDEK(context);
        assertThat(secondRotate.isSuccess()).isTrue();
        UUID newDEKId = secondRotate.getValue().orElseThrow();

        // Verify getActiveDEK now returns the new DEK
        Result<DEKWithMetadata, KeyError> activeAfter = keyManager.getActiveDEK(context);
        assertThat(activeAfter.isSuccess())
                .as("getActiveDEK should succeed after rotation for context %s", context)
                .isTrue();

        UUID activeDEKId = activeAfter.getValue().orElseThrow().getKeyId();
        assertThat(activeDEKId)
                .as("After rotation, getActiveDEK must return the new DEK ID %s", newDEKId)
                .isEqualTo(newDEKId);

        assertThat(activeDEKId)
                .as("After rotation, getActiveDEK must NOT return the old DEK ID %s", oldDEKId)
                .isNotEqualTo(oldDEKId);
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
     *
     * <p>Each call to {@code generateKEK} creates a fresh random KEK ID and stores
     * a random 256-bit KEK. {@code encryptDEK} and {@code decryptDEK} use AES-GCM
     * to wrap/unwrap the DEK bytes with the stored KEK material.
     */
    private static final class StubKmsClient implements IKMSClient {

        /** KEK ID → raw 256-bit KEK bytes */
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
                // Prepend IV to the encrypted DEK bytes for later decryption
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
