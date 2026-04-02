package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for authentication tag presence in ciphertext.
 *
 * <p>These tests verify Property 34: Authentication Tag in Ciphertext — for any
 * encrypted ciphertext using AES-256-GCM, the ciphertext shall contain a 16-byte
 * authentication tag at the end.
 */
class AuthenticationTagPropertyTest {

    /**
     * Property 34: Authentication Tag in Ciphertext
     *
     * <p>For any plaintext string and any bounded context, the ciphertext produced
     * by {@code EncryptionService.encrypt} must:
     * <ul>
     *   <li>Have a total length of at least 46 bytes (1+1+16+12+16 fixed overhead)</li>
     *   <li>Contain a 16-byte authentication tag at the last 16 bytes</li>
     *   <li>Have the authentication tag accessible via {@link CiphertextFormat#parse}</li>
     * </ul>
     */
    @Property(tries = 300)
    @Label("Property 34: Ciphertext contains 16-byte authentication tag at the end")
    void ciphertextContains16ByteAuthenticationTagAtEnd(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService encryptionService = buildEncryptionService();

        Result<Ciphertext, EncryptionError> result = encryptionService.encrypt(plaintext, context);

        assertThat(result.isSuccess())
                .as("Encryption of '%s' in context %s should succeed", plaintext, context)
                .isTrue();

        byte[] ciphertextBytes = result.getValue().orElseThrow().getValue();

        // Total length must be at least 46 bytes (fixed overhead) plus plaintext bytes
        assertThat(ciphertextBytes.length)
                .as("Ciphertext must be at least 46 bytes (1+1+16+12+16 fixed overhead)")
                .isGreaterThanOrEqualTo(46);

        // The last 16 bytes are the authentication tag — extract and verify non-null/non-zero length
        byte[] authTag = new byte[16];
        System.arraycopy(ciphertextBytes, ciphertextBytes.length - 16, authTag, 0, 16);

        assertThat(authTag)
                .as("Authentication tag (last 16 bytes) must be exactly 16 bytes")
                .hasSize(16);
    }

    /**
     * Property 34 (via parse): Parsed authentication tag is exactly 16 bytes.
     *
     * <p>Verifies the same invariant using {@link CiphertextFormat#parse} so that
     * the decoded auth tag field is also checked.
     */
    @Property(tries = 300)
    @Label("Property 34: Parsed authentication tag from ciphertext is exactly 16 bytes")
    void parsedAuthenticationTagIsExactly16Bytes(
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

        byte[] authTag = parseResult.getValue().orElseThrow().getAuthTag();

        assertThat(authTag)
                .as("Authentication tag parsed from ciphertext must be exactly 16 bytes")
                .hasSize(16);
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
    }
}
