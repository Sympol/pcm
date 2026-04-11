package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;
import net.jqwik.api.constraints.NotEmpty;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for encryption/decryption round-trip correctness.
 *
 * <p>These tests verify Property 1: Encryption/Decryption Round-Trip — for any
 * plaintext PII data and bounded context, encrypting then decrypting should
 * produce the original plaintext value.
 */
class EncryptionRoundTripPropertyTest {

    /**
     * Property 1: Encryption/Decryption Round-Trip
     *
     * <p>For any plaintext string and any bounded context, encrypting the plaintext
     * and then decrypting the resulting ciphertext must produce the original plaintext.
     *
     * <p>This property validates:
     * <ul>
     *   <li>Encrypted data retrieved from the database is decrypted
     *       before returning it to the Domain Layer</li>
     *   <li>The IV is correctly extracted from the stored ciphertext
     *       format during decryption</li>
     * </ul>
     */
    @Property(tries = 300)
    @Label("Encrypting then decrypting produces the original plaintext")
    void encryptThenDecryptProducesOriginalPlaintext(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService encryptionService = buildEncryptionService();

        // Encrypt
        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(plaintext, context);

        assertThat(encryptResult.isSuccess())
                .as("Encryption of '%s' in context %s should succeed", plaintext, context)
                .isTrue();

        Ciphertext ciphertext = encryptResult.getValue().orElseThrow();

        // Decrypt
        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(ciphertext, context);

        assertThat(decryptResult.isSuccess())
                .as("Decryption should succeed for ciphertext produced from '%s' in context %s",
                        plaintext, context)
                .isTrue();

        String decrypted = decryptResult.getValue().orElseThrow();

        assertThat(decrypted)
                .as("Decrypted value must equal the original plaintext")
                .isEqualTo(plaintext);
    }

    /**
     * Property 1 (edge cases): Round-trip holds for empty strings.
     */
    @Property(tries = 50)
    @Label("Round-trip holds for empty string plaintext")
    void roundTripHoldsForEmptyString(
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService encryptionService = buildEncryptionService();

        String plaintext = "";

        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(plaintext, context);

        assertThat(encryptResult.isSuccess())
                .as("Encryption of empty string should succeed")
                .isTrue();

        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(encryptResult.getValue().orElseThrow(), context);

        assertThat(decryptResult.isSuccess())
                .as("Decryption of empty-string ciphertext should succeed")
                .isTrue();

        assertThat(decryptResult.getValue().orElseThrow())
                .as("Decrypted empty string must equal original empty string")
                .isEqualTo(plaintext);
    }

    /**
     * Property 1 (unicode): Round-trip holds for unicode and special characters.
     */
    @Property(tries = 100)
    @Label("Round-trip holds for unicode and special character plaintext")
    void roundTripHoldsForUnicodePlaintext(
            @ForAll("unicodePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService encryptionService = buildEncryptionService();

        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(plaintext, context);

        assertThat(encryptResult.isSuccess())
                .as("Encryption of unicode plaintext should succeed")
                .isTrue();

        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(encryptResult.getValue().orElseThrow(), context);

        assertThat(decryptResult.isSuccess())
                .as("Decryption of unicode ciphertext should succeed")
                .isTrue();

        assertThat(decryptResult.getValue().orElseThrow())
                .as("Decrypted unicode value must equal original plaintext")
                .isEqualTo(plaintext);
    }

    /**
     * Property 1 (long strings): Round-trip holds for very long strings (>1KB).
     */
    @Property(tries = 50)
    @Label("Round-trip holds for very long plaintext strings")
    void roundTripHoldsForLongPlaintext(
            @ForAll("longPlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService encryptionService = buildEncryptionService();

        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(plaintext, context);

        assertThat(encryptResult.isSuccess())
                .as("Encryption of long plaintext (%d chars) should succeed", plaintext.length())
                .isTrue();

        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(encryptResult.getValue().orElseThrow(), context);

        assertThat(decryptResult.isSuccess())
                .as("Decryption of long ciphertext should succeed")
                .isTrue();

        assertThat(decryptResult.getValue().orElseThrow())
                .as("Decrypted long value must equal original plaintext")
                .isEqualTo(plaintext);
    }

    // -------------------------------------------------------------------------
    // Arbitraries
    // -------------------------------------------------------------------------

    /**
     * Generates PII-like plaintext values: emails, phone numbers, names, IP addresses,
     * and general printable ASCII strings.
     */
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

        Arbitrary<String> ipAddresses = Combinators.combine(
                Arbitraries.integers().between(1, 254),
                Arbitraries.integers().between(0, 255),
                Arbitraries.integers().between(0, 255),
                Arbitraries.integers().between(1, 254)
        ).as((a, b, c, d) -> a + "." + b + "." + c + "." + d);

        Arbitrary<String> general = Arbitraries.strings()
                .withCharRange(' ', '~')
                .ofMinLength(0)
                .ofMaxLength(500);

        return Arbitraries.oneOf(emails, phones, names, ipAddresses, general);
    }

    /**
     * Generates unicode and special character strings.
     */
    @Provide
    Arbitrary<String> unicodePlaintext() {
        return Arbitraries.strings()
                .ofMinLength(1)
                .ofMaxLength(200);
    }

    /**
     * Generates long plaintext strings (1KB to 10KB).
     */
    @Provide
    Arbitrary<String> longPlaintext() {
        return Arbitraries.strings()
                .withCharRange(' ', '~')
                .ofMinLength(1024)
                .ofMaxLength(10240);
    }

    /**
     * Generates arbitrary BoundedContext values covering all four contexts.
     */
    @Provide
    Arbitrary<BoundedContext> boundedContext() {
        return Arbitraries.of(BoundedContext.values());
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

    /**
     * Minimal IKeyManager stub that always returns a fixed DEK for any context or key ID.
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
