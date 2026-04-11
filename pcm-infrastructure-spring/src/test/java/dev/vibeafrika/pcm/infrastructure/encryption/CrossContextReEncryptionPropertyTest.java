package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;
import net.jqwik.api.Tuple.Tuple2;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for cross-context data re-encryption.
 *
 * <p>Validates Property 38: Cross-Context Re-encryption — for any data shared from
 * one bounded context to another, the data is decrypted with the source context DEK
 * and re-encrypted with the target context DEK.
 *
 */
class CrossContextReEncryptionPropertyTest {

    /**
     * Property 38: Cross-Context Re-encryption
     *
     * <p>For any plaintext and any pair of distinct bounded contexts (source, target),
     * sharing data across contexts must:
     * <ol>
     *   <li>Succeed and return a valid ciphertext</li>
     *   <li>Produce a ciphertext that decrypts to the original plaintext in the target context</li>
     *   <li>Use the target context's DEK (different key ID than the source ciphertext)</li>
     * </ol>
     */
    @Property(tries = 200)
    @Label("Cross-context sharing decrypts with source DEK and re-encrypts with target DEK")
    void crossContextSharing_decryptsWithSourceAndReEncryptsWithTarget(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("distinctContextPair") Tuple2<BoundedContext, BoundedContext> contextPair) {

        BoundedContext sourceContext = contextPair.get1();
        BoundedContext targetContext = contextPair.get2();

        // Build a service with separate DEKs per context
        PerContextKeyManager keyManager = new PerContextKeyManager();
        EncryptionService encryptionService = buildEncryptionService(keyManager);

        // Encrypt in source context
        Result<Ciphertext, EncryptionError> sourceEncryptResult =
                encryptionService.encrypt(plaintext, sourceContext);
        assertThat(sourceEncryptResult.isSuccess())
                .as("Initial encryption in source context %s should succeed", sourceContext)
                .isTrue();

        Ciphertext sourceCiphertext = sourceEncryptResult.getValue().orElseThrow();
        UUID sourceKeyId = CiphertextFormat.parse(sourceCiphertext).getValue().orElseThrow().getKeyId();

        // Share across contexts (decrypt source, re-encrypt target)
        Result<Ciphertext, EncryptionError> shareResult =
                encryptionService.shareAcrossContexts(sourceCiphertext, sourceContext, targetContext);

        assertThat(shareResult.isSuccess())
                .as("shareAcrossContexts from %s to %s should succeed", sourceContext, targetContext)
                .isTrue();

        Ciphertext targetCiphertext = shareResult.getValue().orElseThrow();

        // The resulting ciphertext must decrypt correctly in the target context
        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(targetCiphertext, targetContext);

        assertThat(decryptResult.isSuccess())
                .as("Decryption of re-encrypted ciphertext in target context %s should succeed", targetContext)
                .isTrue();

        assertThat(decryptResult.getValue().orElseThrow())
                .as("Re-encrypted data must decrypt to the original plaintext")
                .isEqualTo(plaintext);

        // The target ciphertext must use the target context's DEK (different key ID)
        UUID targetKeyId = CiphertextFormat.parse(targetCiphertext).getValue().orElseThrow().getKeyId();
        UUID expectedTargetKeyId = keyManager.getKeyIdForContext(targetContext);

        assertThat(targetKeyId)
                .as("Target ciphertext must use the target context DEK, not the source context DEK")
                .isEqualTo(expectedTargetKeyId)
                .isNotEqualTo(sourceKeyId);
    }

    /**
     * Property 38 (same context): Sharing within the same context is a valid no-op re-encryption.
     *
     * <p>When source and target contexts are the same, the data should still be
     * decrypted and re-encrypted (producing a new ciphertext with a fresh IV).
     */
    @Property(tries = 50)
    @Label("Cross-context sharing within the same context produces a valid re-encryption")
    void crossContextSharing_sameContext_producesValidReEncryption(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService encryptionService = buildEncryptionService(new PerContextKeyManager());

        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(plaintext, context);
        assertThat(encryptResult.isSuccess()).isTrue();

        Ciphertext original = encryptResult.getValue().orElseThrow();

        Result<Ciphertext, EncryptionError> shareResult =
                encryptionService.shareAcrossContexts(original, context, context);

        assertThat(shareResult.isSuccess())
                .as("shareAcrossContexts within the same context %s should succeed", context)
                .isTrue();

        Result<String, DecryptionError> decryptResult =
                encryptionService.decrypt(shareResult.getValue().orElseThrow(), context);

        assertThat(decryptResult.isSuccess()).isTrue();
        assertThat(decryptResult.getValue().orElseThrow())
                .as("Re-encrypted data within same context must equal original plaintext")
                .isEqualTo(plaintext);
    }

    /**
     * Property 38 (wrong context decryption fails): The source ciphertext cannot be
     * decrypted in the target context because it uses a different DEK.
     */
    @Property(tries = 100)
    @Label("Source ciphertext cannot be decrypted in target context (different DEK)")
    void sourceCiphertext_cannotBeDecryptedInTargetContext(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("distinctContextPair") Tuple2<BoundedContext, BoundedContext> contextPair) {

        BoundedContext sourceContext = contextPair.get1();
        BoundedContext targetContext = contextPair.get2();

        EncryptionService encryptionService = buildEncryptionService(new PerContextKeyManager());

        Result<Ciphertext, EncryptionError> encryptResult =
                encryptionService.encrypt(plaintext, sourceContext);
        assertThat(encryptResult.isSuccess()).isTrue();

        Ciphertext sourceCiphertext = encryptResult.getValue().orElseThrow();

        // Attempting to decrypt source ciphertext directly in target context must fail
        // because the DEK used for source is not the active DEK for target
        Result<String, DecryptionError> wrongContextDecrypt =
                encryptionService.decrypt(sourceCiphertext, targetContext);

        assertThat(wrongContextDecrypt.isFailure())
                .as("Decrypting source ciphertext in target context %s should fail "
                        + "(different DEK / AAD mismatch)", targetContext)
                .isTrue();
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

    /**
     * Generates pairs of distinct bounded contexts (source != target).
     */
    @Provide
    Arbitrary<Tuple2<BoundedContext, BoundedContext>> distinctContextPair() {
        return Arbitraries.of(BoundedContext.values()).flatMap(source ->
                Arbitraries.of(BoundedContext.values())
                        .filter(target -> target != source)
                        .map(target -> Tuple.of(source, target))
        );
    }

    // -------------------------------------------------------------------------
    // Test infrastructure
    // -------------------------------------------------------------------------

    private EncryptionService buildEncryptionService(PerContextKeyManager keyManager) {
        IAuditLogger noOpAuditLogger = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        return new EncryptionService(keyManager, blindIndexService, noOpAuditLogger, ivCounter);
    }

    /**
     * A key manager that maintains a separate DEK per bounded context, simulating
     * the real KEK isolation requirement.
     *
     * <p>Each context gets its own fixed DEK so that cross-context operations
     * use genuinely different keys.
     */
    static final class PerContextKeyManager implements IKeyManager {

        private static final SecureRandom RANDOM = new SecureRandom();

        private final java.util.Map<BoundedContext, DEKWithMetadata> dekByContext =
                new java.util.EnumMap<>(BoundedContext.class);

        PerContextKeyManager() {
            for (BoundedContext ctx : BoundedContext.values()) {
                byte[] keyMaterial = new byte[32];
                RANDOM.nextBytes(keyMaterial);
                UUID keyId = UUID.randomUUID();
                DEKWithMetadata meta = DEKWithMetadata.builder()
                        .dek(DEK.of(keyMaterial))
                        .keyId(keyId)
                        .kekId(UUID.randomUUID())
                        .context(ctx)
                        .environment(Environment.DEV)
                        .algorithm(EncryptionAlgorithm.AES_256_GCM)
                        .createdAt(Instant.now())
                        .status(KeyStatus.ACTIVE)
                        .build();
                dekByContext.put(ctx, meta);
            }
        }

        /** Returns the key ID that will be used for a given context. */
        UUID getKeyIdForContext(BoundedContext context) {
            return dekByContext.get(context).getKeyId();
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.success(dekByContext.get(context));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            return dekByContext.values().stream()
                    .filter(m -> m.getKeyId().equals(keyId))
                    .findFirst()
                    .map(Result::<DEKWithMetadata, KeyError>success)
                    .orElseGet(() -> Result.failure(
                            KeyError.of("KEY_NOT_FOUND", "No DEK found for key ID: " + keyId)));
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
            RANDOM.nextBytes(key);
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
