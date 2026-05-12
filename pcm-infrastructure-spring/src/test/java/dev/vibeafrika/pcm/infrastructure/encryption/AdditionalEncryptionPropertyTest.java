package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Additional property-based tests for PII encryption correctness.
 */
class AdditionalEncryptionPropertyTest {

    // =========================================================================
    // Property 3: All PII Fields Encrypted
    // =========================================================================

    /**
     * Property 3: For any PII field type (STANDARD_PII, SENSITIVE_PII, QUASI_IDENTIFIER),
     * the EncryptionService shall encrypt the value — i.e. the result is a valid ciphertext
     * that is NOT equal to the original plaintext bytes.
     */
    @Property(tries = 300)
    @Label("Property 3: All PII field types produce a valid encrypted ciphertext")
    void allPiiFieldTypesAreEncrypted(
            @ForAll("piiValueByType") PiiFieldSample sample) {

        EncryptionService service = buildEncryptionService();

        Result<Ciphertext, EncryptionError> result =
                service.encrypt(sample.value, sample.context);

        assertThat(result.isSuccess())
                .as("Encryption of %s value '%s' in context %s must succeed",
                        sample.piiType, sample.value, sample.context)
                .isTrue();

        byte[] ciphertextBytes = result.getValue().orElseThrow().getValue();

        // Ciphertext must be at least 46 bytes (fixed overhead)
        assertThat(ciphertextBytes.length)
                .as("Ciphertext for %s must be at least 46 bytes", sample.piiType)
                .isGreaterThanOrEqualTo(46);

        // Ciphertext must not equal the plaintext bytes
        byte[] plaintextBytes = sample.value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertThat(ciphertextBytes).isNotEqualTo(plaintextBytes);
    }

    // =========================================================================
    // Property 7: Cryptographically Secure Key Generation
    // =========================================================================

    /**
     * Property 7: For any generated DEK, the key material shall be exactly 256 bits (32 bytes).
     */
    @Property(tries = 200)
    @Label("Property 7: Generated DEKs are exactly 256 bits (32 bytes)")
    void generatedDEKsAreExactly256Bits(@ForAll("boundedContext") BoundedContext context) {

        // Generate a fresh DEK the same way KeyManager does
        SecureRandom secureRandom = new SecureRandom();
        byte[] dekBytes = new byte[32];
        secureRandom.nextBytes(dekBytes);
        DEK dek = DEK.of(dekBytes);

        assertThat(dek.getKeyMaterial())
                .as("DEK key material must be exactly 32 bytes (256 bits) for context %s", context)
                .hasSize(32);
    }

    // =========================================================================
    // Property 13: Field-Level Encryption Independence
    // =========================================================================

    /**
     * Property 13: For any plaintext, encrypting it twice must produce two different
     * ciphertexts (due to unique counter-based IVs). This ensures field-level
     * encryption independence.
     */
    @Property(tries = 300)
    @Label("Property 13: Identical plaintexts produce different ciphertexts (unique IVs)")
    void identicalPlaintextsProduceDifferentCiphertexts(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService service = buildEncryptionService();

        Result<Ciphertext, EncryptionError> first = service.encrypt(plaintext, context);
        Result<Ciphertext, EncryptionError> second = service.encrypt(plaintext, context);

        assertThat(first.isSuccess()).isTrue();
        assertThat(second.isSuccess()).isTrue();

        assertThat(first.getValue().orElseThrow().getValue())
                .as("Two encryptions of '%s' must produce different ciphertexts (unique IVs)", plaintext)
                .isNotEqualTo(second.getValue().orElseThrow().getValue());
    }

    // =========================================================================
    // Property 29: Batch Operations Correctness
    // =========================================================================

    /**
     * Property 29: For any batch of plaintexts, encrypting the batch then decrypting
     * the batch must produce the original plaintexts in the same order.
     */
    @Property(tries = 200)
    @Label("Property 29: Batch encrypt then decrypt preserves all plaintexts in order")
    void batchEncryptThenDecryptPreservesOrder(
            @ForAll("plaintextBatch") List<String> plaintexts,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService service = buildEncryptionService();

        Result<List<Ciphertext>, EncryptionError> encResult =
                service.encryptBatch(plaintexts, context);

        assertThat(encResult.isSuccess())
                .as("Batch encryption of %d items in context %s must succeed",
                        plaintexts.size(), context)
                .isTrue();

        List<Ciphertext> ciphertexts = encResult.getValue().orElseThrow();

        assertThat(ciphertexts)
                .as("Batch encryption must produce same number of ciphertexts as plaintexts")
                .hasSize(plaintexts.size());

        Result<List<String>, DecryptionError> decResult =
                service.decryptBatch(ciphertexts, context);

        assertThat(decResult.isSuccess())
                .as("Batch decryption must succeed")
                .isTrue();

        List<String> decrypted = decResult.getValue().orElseThrow();

        assertThat(decrypted)
                .as("Batch decrypt must return plaintexts in original order")
                .containsExactlyElementsOf(plaintexts);
    }

    // =========================================================================
    // Property 33: Algorithm Identifier in Ciphertext
    // =========================================================================

    /**
     * Property 33: For any encrypted ciphertext, byte 1 must contain the algorithm
     * identifier, and CiphertextFormat.parse must return the matching algorithm enum.
     */
    @Property(tries = 300)
    @Label("Property 33: Ciphertext byte 1 contains the algorithm identifier")
    void ciphertextContainsAlgorithmIdentifierAtByteOne(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService service = buildEncryptionService();

        Result<Ciphertext, EncryptionError> encResult = service.encrypt(plaintext, context);
        assertThat(encResult.isSuccess()).isTrue();

        byte[] bytes = encResult.getValue().orElseThrow().getValue();

        // Byte 1 must be a known algorithm ID
        byte algorithmId = bytes[1];
        assertThat(algorithmId)
                .as("Algorithm ID at byte 1 must be 0x01 (AES-256-GCM) or 0x02 (AES-256-CBC)")
                .isIn(CiphertextFormat.ALGORITHM_AES_256_GCM, CiphertextFormat.ALGORITHM_AES_256_CBC_HMAC);

        // Parsed algorithm must match the byte
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult =
                CiphertextFormat.parse(encResult.getValue().orElseThrow());
        assertThat(parseResult.isSuccess()).isTrue();

        byte parsedId = CiphertextFormat.algorithmToId(
                parseResult.getValue().orElseThrow().getAlgorithm());
        assertThat(parsedId)
                .as("Parsed algorithm ID must match raw byte 1")
                .isEqualTo(algorithmId);
    }

    // =========================================================================
    // Property 35: Metadata in Authentication
    // =========================================================================

    /**
     * Property 35: For any two ciphertexts with identical plaintext but different
     * bounded contexts (different AAD/metadata), swapping the ciphertexts must be
     * detected as tampering during decryption.
     */
    @Property(tries = 200)
    @Label("Property 35: Ciphertext from context A cannot be decrypted in context B")
    void ciphertextFromOneContextFailsDecryptionInAnotherContext(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("twoDistinctContexts") List<BoundedContext> contexts) {

        BoundedContext contextA = contexts.get(0);
        BoundedContext contextB = contexts.get(1);

        // Use a shared key manager so the same DEK is available in both contexts
        UUID dekId = UUID.randomUUID();
        SharedKeyManager sharedKeyManager = new SharedKeyManager(dekId);
        EncryptionService service = buildEncryptionServiceWith(sharedKeyManager);

        // Encrypt in context A
        Result<Ciphertext, EncryptionError> encResult = service.encrypt(plaintext, contextA);
        assertThat(encResult.isSuccess())
                .as("Encryption in context %s must succeed", contextA)
                .isTrue();

        Ciphertext ciphertextFromA = encResult.getValue().orElseThrow();

        // Attempt to decrypt in context B — must fail because AAD differs
        Result<String, DecryptionError> decResult = service.decrypt(ciphertextFromA, contextB);

        assertThat(decResult.isSuccess())
                .as("Decrypting context-%s ciphertext in context %s must fail (AAD mismatch = tampering)",
                        contextA, contextB)
                .isFalse();
    }

    // =========================================================================
    // Property 36: Tampering Triggers Audit Log
    // =========================================================================

    /**
     * Property 36: For any tampered ciphertext, decryption must fail AND a security
     * audit log entry must be created with event type TAMPERING_DETECTED.
     */
    @Property(tries = 200)
    @Label("Property 36: Tampering detection creates a security audit log entry")
    void tamperingDetectionCreatesSecurityAuditLog(
            @ForAll("nonEmptyPlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        CapturingAuditLogger auditLogger = new CapturingAuditLogger();
        UUID dekId = UUID.randomUUID();
        IKeyManager keyManager = new StubKeyManager(dekId);
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-salt");
        EncryptionService service = new EncryptionService(keyManager, blindIndexService, auditLogger, ivCounter);

        // Encrypt to get a valid ciphertext
        Result<Ciphertext, EncryptionError> encResult = service.encrypt(plaintext, context);
        assertThat(encResult.isSuccess()).isTrue();

        // Tamper: flip the last byte of the auth tag
        byte[] bytes = encResult.getValue().orElseThrow().getValue().clone();
        bytes[bytes.length - 1] = (byte) ~bytes[bytes.length - 1];
        Ciphertext tampered = Ciphertext.of(bytes);

        auditLogger.clearSecurityEvents();

        // Decrypt the tampered ciphertext
        Result<String, DecryptionError> decResult = service.decrypt(tampered, context);

        assertThat(decResult.isSuccess())
                .as("Decryption of tampered ciphertext must fail")
                .isFalse();

        assertThat(auditLogger.getCapturedSecurityEvents())
                .as("A security audit log entry must be created on tampering detection")
                .isNotEmpty();

        boolean hasTamperingEvent = auditLogger.getCapturedSecurityEvents().stream()
                .anyMatch(e -> e.getEventType() != null &&
                        e.getEventType().contains("TAMPERING"));
        assertThat(hasTamperingEvent)
                .as("Security event must reference TAMPERING")
                .isTrue();
    }

    // =========================================================================
    // Property 46: Algorithm ID for AES-256-GCM
    // =========================================================================

    /**
     * Property 46: For any ciphertext produced by the default EncryptionService,
     * byte 1 must be 0x01 (AES-256-GCM algorithm ID).
     */
    @Property(tries = 300)
    @Label("Property 46: AES-256-GCM ciphertext has algorithm_id 0x01 at byte 1")
    void aesGcmCiphertextHasAlgorithmId0x01(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService service = buildEncryptionService();

        Result<Ciphertext, EncryptionError> result = service.encrypt(plaintext, context);
        assertThat(result.isSuccess()).isTrue();

        byte algorithmId = result.getValue().orElseThrow().getValue()[1];
        assertThat(algorithmId)
                .as("AES-256-GCM ciphertext must have algorithm_id 0x01 at byte 1")
                .isEqualTo(CiphertextFormat.ALGORITHM_AES_256_GCM);
    }

    // =========================================================================
    // Property 47: Algorithm ID for AES-256-CBC
    // =========================================================================

    /**
     * Property 47: For any ciphertext formatted with algorithm ID 0x02,
     * CiphertextFormat.parse must return EncryptionAlgorithm.AES_256_CBC_HMAC.
     */
    @Property(tries = 200)
    @Label("Property 47: AES-256-CBC formatted ciphertext has algorithm_id 0x02")
    void aesCbcFormattedCiphertextHasAlgorithmId0x02(
            @ForAll("validKeyId") UUID keyId,
            @ForAll("validIV") byte[] iv,
            @ForAll("validCiphertextBody") byte[] body,
            @ForAll("validAuthTag") byte[] authTag) {

        Result<Ciphertext, DecryptionError> formatResult = CiphertextFormat.format(
                CiphertextFormat.VERSION_1,
                CiphertextFormat.ALGORITHM_AES_256_CBC_HMAC,
                keyId,
                iv,
                body,
                authTag
        );

        assertThat(formatResult.isSuccess())
                .as("Formatting with CBC algorithm ID must succeed")
                .isTrue();

        byte[] bytes = formatResult.getValue().orElseThrow().getValue();

        assertThat(bytes[1])
                .as("Byte 1 must be 0x02 for AES-256-CBC")
                .isEqualTo(CiphertextFormat.ALGORITHM_AES_256_CBC_HMAC);

        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult =
                CiphertextFormat.parse(formatResult.getValue().orElseThrow());
        assertThat(parseResult.isSuccess()).isTrue();

        assertThat(parseResult.getValue().orElseThrow().getAlgorithm())
                .as("Parsed algorithm must be AES_256_CBC_HMAC")
                .isEqualTo(EncryptionAlgorithm.AES_256_CBC_HMAC);
    }

    // =========================================================================
    // Property 48: Key ID UUID Format
    // =========================================================================

    /**
     * Property 48: For any encrypted ciphertext, the key_id stored at bytes 2-17
     * must be the UUID of the DEK used for encryption, in big-endian format.
     */
    @Property(tries = 300)
    @Label("Property 48: Key ID is stored as 128-bit UUID in big-endian at bytes 2-17")
    void keyIdStoredAsBigEndianUUIDAtBytes2To17(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        UUID dekId = UUID.randomUUID();
        StubKeyManager keyManager = new StubKeyManager(dekId);
        EncryptionService service = buildEncryptionServiceWith(keyManager);

        Result<Ciphertext, EncryptionError> result = service.encrypt(plaintext, context);
        assertThat(result.isSuccess()).isTrue();

        byte[] bytes = result.getValue().orElseThrow().getValue();

        // Extract UUID from bytes 2-17 (big-endian)
        long msb = 0;
        long lsb = 0;
        for (int i = 2; i < 10; i++) msb = (msb << 8) | (bytes[i] & 0xFF);
        for (int i = 10; i < 18; i++) lsb = (lsb << 8) | (bytes[i] & 0xFF);
        UUID extractedKeyId = new UUID(msb, lsb);

        assertThat(extractedKeyId)
                .as("Key ID at bytes 2-17 must equal the DEK UUID used for encryption")
                .isEqualTo(dekId);
    }

    // =========================================================================
    // Property 49: Unsupported Version Rejection
    // =========================================================================

    /**
     * Property 49: For any ciphertext with an unsupported version byte (not 0x01),
     * CiphertextFormat.parse must return a failure with code UNSUPPORTED_VERSION.
     */
    @Property(tries = 200)
    @Label("Property 49: Unsupported version bytes are rejected with UNSUPPORTED_VERSION error")
    void unsupportedVersionBytesAreRejected(
            @ForAll("unsupportedVersionByte") byte version,
            @ForAll("validKeyId") UUID keyId,
            @ForAll("validIV") byte[] iv,
            @ForAll("validCiphertextBody") byte[] body,
            @ForAll("validAuthTag") byte[] authTag) {

        // Build a raw byte array with the unsupported version
        byte[] raw = new byte[1 + 1 + 16 + 12 + body.length + 16];
        raw[0] = version;
        raw[1] = CiphertextFormat.ALGORITHM_AES_256_GCM;
        // key_id at bytes 2-17
        long msb = keyId.getMostSignificantBits();
        long lsb = keyId.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) raw[2 + i] = (byte) (msb >>> (56 - 8 * i));
        for (int i = 0; i < 8; i++) raw[10 + i] = (byte) (lsb >>> (56 - 8 * i));
        System.arraycopy(iv, 0, raw, 18, 12);
        System.arraycopy(body, 0, raw, 30, body.length);
        System.arraycopy(authTag, 0, raw, 30 + body.length, 16);

        Ciphertext ciphertext = Ciphertext.of(raw);
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> result =
                CiphertextFormat.parse(ciphertext);

        assertThat(result.isSuccess())
                .as("Parsing ciphertext with unsupported version 0x%02X must fail", version)
                .isFalse();

        assertThat(result.getError().orElseThrow().getCode())
                .as("Error code must be UNSUPPORTED_VERSION for version byte 0x%02X", version)
                .isEqualTo("UNSUPPORTED_VERSION");
    }

    // =========================================================================
    // Property 50: Backward Compatibility
    // =========================================================================

    /**
     * Property 50: Ciphertexts produced with VERSION_1 (the only supported version)
     * must always be parseable and decryptable — ensuring backward compatibility
     * for all data encrypted under the current format version.
     */
    @Property(tries = 200)
    @Label("Property 50: VERSION_1 ciphertexts are always parseable (backward compatibility)")
    void version1CiphertextsAreAlwaysParseable(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService service = buildEncryptionService();

        Result<Ciphertext, EncryptionError> encResult = service.encrypt(plaintext, context);
        assertThat(encResult.isSuccess()).isTrue();

        Ciphertext ciphertext = encResult.getValue().orElseThrow();

        // Version byte must be VERSION_1
        assertThat(ciphertext.getValue()[0])
                .as("Ciphertext version byte must be VERSION_1 (0x01)")
                .isEqualTo(CiphertextFormat.VERSION_1);

        // Must be parseable
        Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult =
                CiphertextFormat.parse(ciphertext);
        assertThat(parseResult.isSuccess())
                .as("VERSION_1 ciphertext must always be parseable")
                .isTrue();

        // Must be decryptable (round-trip)
        Result<String, DecryptionError> decResult = service.decrypt(ciphertext, context);
        assertThat(decResult.isSuccess())
                .as("VERSION_1 ciphertext must always be decryptable")
                .isTrue();
        assertThat(decResult.getValue().orElseThrow())
                .as("Decrypted value must equal original plaintext")
                .isEqualTo(plaintext);
    }

    // =========================================================================
    // Arbitraries
    // =========================================================================

    @Provide
    Arbitrary<String> piiLikePlaintext() {
        Arbitrary<String> emails = Combinators.combine(
                Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(20),
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(10),
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(5)
        ).as((u, d, t) -> u + "@" + d + "." + t);

        Arbitrary<String> phones = Arbitraries.integers().between(100000000, 999999999)
                .map(n -> "+1" + n);

        Arbitrary<String> names = Combinators.combine(
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(15),
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(15)
        ).as((f, l) -> f + " " + l);

        Arbitrary<String> general = Arbitraries.strings()
                .withCharRange(' ', '~')
                .ofMinLength(1)
                .ofMaxLength(200);

        return Arbitraries.oneOf(emails, phones, names, general);
    }

    @Provide
    Arbitrary<String> nonEmptyPlaintext() {
        return Arbitraries.strings().withCharRange(' ', '~').ofMinLength(1).ofMaxLength(200);
    }

    @Provide
    Arbitrary<BoundedContext> boundedContext() {
        return Arbitraries.of(BoundedContext.values());
    }

    @Provide
    Arbitrary<List<String>> plaintextBatch() {
        return Arbitraries.strings()
                .withCharRange(' ', '~')
                .ofMinLength(1)
                .ofMaxLength(100)
                .list()
                .ofMinSize(1)
                .ofMaxSize(20);
    }

    @Provide
    Arbitrary<List<BoundedContext>> twoDistinctContexts() {
        return Arbitraries.of(BoundedContext.values())
                .list()
                .ofSize(2)
                .filter(list -> list.get(0) != list.get(1));
    }

    @Provide
    Arbitrary<PiiFieldSample> piiValueByType() {
        Arbitrary<PiiFieldSample> standardPii = Combinators.combine(
                Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(15),
                Arbitraries.strings().alpha().ofMinLength(2).ofMaxLength(8),
                Arbitraries.of(BoundedContext.values())
        ).as((u, d, ctx) -> new PiiFieldSample(
                PIIType.STANDARD_PII, u + "@" + d + ".com", ctx));

        Arbitrary<PiiFieldSample> sensitivePii = Combinators.combine(
                Arbitraries.strings().alpha().ofMinLength(3).ofMaxLength(30),
                Arbitraries.of(BoundedContext.values())
        ).as((v, ctx) -> new PiiFieldSample(PIIType.SENSITIVE_PII, v, ctx));

        Arbitrary<PiiFieldSample> quasiId = Combinators.combine(
                Arbitraries.integers().between(1, 254),
                Arbitraries.integers().between(0, 255),
                Arbitraries.integers().between(0, 255),
                Arbitraries.integers().between(1, 254),
                Arbitraries.of(BoundedContext.values())
        ).as((a, b, c, d, ctx) -> new PiiFieldSample(
                PIIType.QUASI_IDENTIFIER, a + "." + b + "." + c + "." + d, ctx));

        return Arbitraries.oneOf(standardPii, sensitivePii, quasiId);
    }

    @Provide
    Arbitrary<UUID> validKeyId() {
        return Arbitraries.randomValue(r -> UUID.randomUUID());
    }

    @Provide
    Arbitrary<byte[]> validIV() {
        return Arbitraries.bytes().array(byte[].class).ofSize(12);
    }

    @Provide
    Arbitrary<byte[]> validCiphertextBody() {
        return Arbitraries.bytes().array(byte[].class).ofMinSize(0).ofMaxSize(200);
    }

    @Provide
    Arbitrary<byte[]> validAuthTag() {
        return Arbitraries.bytes().array(byte[].class).ofSize(16);
    }

    /** Generates version bytes that are NOT VERSION_1 (0x01). */
    @Provide
    Arbitrary<Byte> unsupportedVersionByte() {
        return Arbitraries.bytes().filter(b -> b != CiphertextFormat.VERSION_1);
    }

    // =========================================================================
    // Test infrastructure
    // =========================================================================

    private EncryptionService buildEncryptionService() {
        UUID dekId = UUID.randomUUID();
        return buildEncryptionServiceWith(new StubKeyManager(dekId));
    }

    private EncryptionService buildEncryptionServiceWith(IKeyManager keyManager) {
        IAuditLogger noOp = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        return new EncryptionService(keyManager, blindIndexService, noOp, ivCounter);
    }

    /** Simple value holder for PII field type + value + context. */
    static final class PiiFieldSample {
        final PIIType piiType;
        final String value;
        final BoundedContext context;

        PiiFieldSample(PIIType piiType, String value, BoundedContext context) {
            this.piiType = piiType;
            this.value = value;
            this.context = context;
        }
    }

    /** Stub IKeyManager that always returns the same DEK for any context or key ID. */
    private static class StubKeyManager implements IKeyManager {

        private final UUID keyId;
        private final DEK dek;

        StubKeyManager(UUID keyId) {
            this.keyId = keyId;
            byte[] material = new byte[32];
            new SecureRandom().nextBytes(material);
            this.dek = DEK.of(material);
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.success(meta(context));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID id) {
            return Result.success(meta(BoundedContext.PROFILE));
        }

        private DEKWithMetadata meta(BoundedContext ctx) {
            return DEKWithMetadata.builder()
                    .dek(dek).keyId(keyId).kekId(UUID.randomUUID())
                    .context(ctx).environment(Environment.DEV)
                    .algorithm(EncryptionAlgorithm.AES_256_GCM)
                    .createdAt(Instant.now()).status(KeyStatus.ACTIVE)
                    .build();
        }

        @Override public Result<UUID, KeyError> rotateDEK(BoundedContext c) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "n/a"));
        }
        @Override public Result<UUID, KeyError> rotateKEK(BoundedContext c) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "n/a"));
        }
        @Override public Result<Void, KeyError> invalidateCache(UUID id) {
            return Result.success(null);
        }
        @Override public Result<DeletionCertificate, KeyError> deleteUserDEK(String u, BoundedContext c) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "n/a"));
        }
        @Override public Result<byte[], KeyError> getBlindIndexKey() {
            byte[] k = new byte[32];
            new SecureRandom().nextBytes(k);
            return Result.success(k);
        }
    }

    /**
     * Shared key manager that returns the same DEK regardless of context,
     * allowing cross-context AAD mismatch tests (Property 35).
     */
    private static final class SharedKeyManager extends StubKeyManager {
        SharedKeyManager(UUID dekId) { super(dekId); }
    }

        /** No-op IAuditLogger that discards all events. */
    private static final class NoOpAuditLogger implements IAuditLogger {
        private static final AuditError NOOP = AuditError.of("NOOP", "no-op");

        @Override public Result<Void, AuditError> logEncryption(EncryptionEvent e) { return Result.failure(NOOP); }
        @Override public Result<Void, AuditError> logDecryption(DecryptionEvent e) { return Result.failure(NOOP); }
        @Override public Result<Void, AuditError> logKeyRotation(KeyRotationEvent e) { return Result.failure(NOOP); }
        @Override public Result<Void, AuditError> logSecurityEvent(SecurityEvent e) { return Result.failure(NOOP); }
        @Override public Result<Void, AuditError> logKeyAccess(KeyAccessEvent e) { return Result.failure(NOOP); }
        @Override public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent e) { return Result.failure(NOOP); }
    }

    /**
     * Capturing IAuditLogger that records security events for assertion in Property 36.
     */
    private static final class CapturingAuditLogger implements IAuditLogger {
        private static final AuditError NOOP = AuditError.of("NOOP", "no-op");
        private final List<SecurityEvent> securityEvents = new CopyOnWriteArrayList<>();

        void clearSecurityEvents() { securityEvents.clear(); }
        List<SecurityEvent> getCapturedSecurityEvents() { return securityEvents; }

        @Override public Result<Void, AuditError> logEncryption(EncryptionEvent e) { return Result.failure(NOOP); }
        @Override public Result<Void, AuditError> logDecryption(DecryptionEvent e) { return Result.failure(NOOP); }
        @Override public Result<Void, AuditError> logKeyRotation(KeyRotationEvent e) { return Result.failure(NOOP); }
        @Override public Result<Void, AuditError> logKeyAccess(KeyAccessEvent e) { return Result.failure(NOOP); }
        @Override public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent e) { return Result.failure(NOOP); }

        @Override
        public Result<Void, AuditError> logSecurityEvent(SecurityEvent event) {
            securityEvents.add(event);
            return Result.success(null);
        }
    }
}

