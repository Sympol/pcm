package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for AES-256-GCM algorithm usage.
 *
 * <p>These tests verify Property 2: AES-256-GCM Algorithm Usage — for any
 * plaintext PII data and bounded context, the resulting ciphertext must use
 * AES-256-GCM (algorithm ID 0x01 at byte index 1).
 */
class AesGcmAlgorithmPropertyTest {

    /**
     * Property 2: AES-256-GCM Algorithm Usage
     *
     * <p>For any plaintext string and any bounded context, the ciphertext produced
     * by {@code EncryptionService.encrypt} must have algorithm ID byte {@code 0x01}
     * (AES-256-GCM) at position 1 in the binary format:
     * {@code [version(1)][algorithm_id(1)][key_id(16)][IV(12)][ciphertext(N)][tag(16)]}.
     */
    @Property(tries = 300)
    @Label("All encrypted data uses AES-256-GCM (algorithm ID 0x01)")
    void allEncryptedDataUsesAesGcm(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService encryptionService = buildEncryptionService();

        Result<Ciphertext, EncryptionError> result = encryptionService.encrypt(plaintext, context);

        assertThat(result.isSuccess())
                .as("Encryption of '%s' in context %s should succeed", plaintext, context)
                .isTrue();

        byte[] ciphertextBytes = result.getValue().orElseThrow().getValue();

        // Algorithm ID is at byte index 1 in the ciphertext format
        assertThat(ciphertextBytes[1])
                .as("Algorithm ID byte at index 1 must be 0x01 (AES-256-GCM) for plaintext '%s' in context %s",
                        plaintext, context)
                .isEqualTo(CiphertextFormat.ALGORITHM_AES_256_GCM);
    }

    /**
     * Property 2 (via parse): Parsed algorithm field equals AES_256_GCM enum.
     *
     * <p>Verifies the same invariant using {@link CiphertextFormat#parse} so that
     * both the raw byte and the decoded enum are checked.
     */
    @Property(tries = 300)
    @Label("Parsed algorithm from ciphertext is AES_256_GCM for all inputs")
    void parsedAlgorithmIsAesGcm(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService encryptionService = buildEncryptionService();

        Result<Ciphertext, EncryptionError> encryptResult = encryptionService.encrypt(plaintext, context);

        assertThat(encryptResult.isSuccess())
                .as("Encryption should succeed")
                .isTrue();

        Ciphertext ciphertext = encryptResult.getValue().orElseThrow();

        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult =
                CiphertextFormat.parse(ciphertext);

        assertThat(parseResult.isSuccess())
                .as("Parsing the produced ciphertext should succeed")
                .isTrue();

        assertThat(parseResult.getValue().orElseThrow().getAlgorithm())
                .as("Parsed algorithm must be AES_256_GCM")
                .isEqualTo(EncryptionAlgorithm.AES_256_GCM);
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
                .ofMaxLength(500);

        return Arbitraries.oneOf(emails, phones, names, general);
    }

    @Provide
    Arbitrary<BoundedContext> boundedContext() {
        return Arbitraries.of(BoundedContext.values());
    }

    // -------------------------------------------------------------------------
    // Test infrastructure
    // -------------------------------------------------------------------------

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

        @Override
        public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent event) {
            return Result.failure(NOOP);
        }
    }
}
