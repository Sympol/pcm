package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import net.jqwik.api.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for Property 26: Encryption Failure Prevents Storage.
 *
 * <p><b>Validates: </b>
 *
 * <p>IF encryption fails during data persistence, THEN THE
 * Encryption_Service SHALL return a descriptive error and prevent data storage.
 *
 * <p>This property verifies that when encryption fails for any reason (KMS unavailable,
 * key not found, encryption algorithm failure), the {@link EncryptionService} returns a
 * {@link Result} failure — meaning no {@link Ciphertext} value is produced. Since the
 * persistence layer can only store data by obtaining a {@code Ciphertext} from the
 * {@code Result}, the absence of a value in the failure case is the mechanism that
 * prevents data storage.
 *
 * <p>Failure scenarios covered:
 * <ul>
 *   <li>KMS unavailable — {@code getActiveDEK} returns {@code KEY_UNAVAILABLE}</li>
 *   <li>Key not found — {@code getActiveDEK} returns {@code KEY_NOT_FOUND}</li>
 *   <li>KMS authentication failure — {@code getActiveDEK} returns {@code KMS_AUTHENTICATION_FAILED}</li>
 *   <li>KMS timeout — {@code getActiveDEK} returns {@code KMS_TIMEOUT}</li>
 *   <li>IV generation failure — {@link IVCounter} always fails</li>
 * </ul>
 */
class EncryptionFailurePreventsStoragePropertyTest {

    // =========================================================================
    // Property 26: Encryption Failure Prevents Storage
    // =========================================================================

    /**
     * Property 26 (KMS unavailable): For any plaintext and any bounded context,
     * when the KMS is unavailable, the encryption result SHALL be a failure and
     * SHALL NOT contain a ciphertext value.
     */
    @Property(tries = 200)
    @Label("Property 26: KMS unavailable — encryption returns failure with no ciphertext value")
    void kmsUnavailable_encryptionReturnsFailureWithNoCiphertextValue(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService service = buildServiceWithKeyError(
                EncryptionErrorCodes.KMS_UNAVAILABLE.code(),
                "KMS is unavailable"
        );

        Result<Ciphertext, EncryptionError> result = service.encrypt(plaintext, context);

        assertThat(result.isFailure())
                .as("Encryption must fail when KMS is unavailable (plaintext='%s', context=%s)",
                        plaintext, context)
                .isTrue();

        assertThat(result.getValue())
                .as("No ciphertext value must be present when encryption fails — "
                        + "this prevents data storage")
                .isEmpty();

        assertThat(result.getError())
                .as("A descriptive error must be present when encryption fails")
                .isPresent();

        assertThat(result.getError().orElseThrow().getMessage())
                .as("Error message must be non-blank")
                .isNotBlank();
    }

    /**
     * Property 26 (key not found): For any plaintext and any bounded context,
     * when the encryption key is not found, the encryption result SHALL be a failure
     * and SHALL NOT contain a ciphertext value.
     */
    @Property(tries = 200)
    @Label("Property 26: Key not found — encryption returns failure with no ciphertext value")
    void keyNotFound_encryptionReturnsFailureWithNoCiphertextValue(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService service = buildServiceWithKeyError(
                EncryptionErrorCodes.KEY_NOT_FOUND.code(),
                "Encryption key not found"
        );

        Result<Ciphertext, EncryptionError> result = service.encrypt(plaintext, context);

        assertThat(result.isFailure())
                .as("Encryption must fail when key is not found (plaintext='%s', context=%s)",
                        plaintext, context)
                .isTrue();

        assertThat(result.getValue())
                .as("No ciphertext value must be present when key is not found — "
                        + "this prevents data storage")
                .isEmpty();

        assertThat(result.getError())
                .as("A descriptive error must be present when key is not found")
                .isPresent();
    }

    /**
     * Property 26 (KMS authentication failure): For any plaintext and any bounded context,
     * when KMS authentication fails, the encryption result SHALL be a failure and
     * SHALL NOT contain a ciphertext value.
     */
    @Property(tries = 200)
    @Label("Property 26: KMS authentication failure — encryption returns failure with no ciphertext value")
    void kmsAuthenticationFailure_encryptionReturnsFailureWithNoCiphertextValue(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService service = buildServiceWithKeyError(
                EncryptionErrorCodes.KMS_AUTHENTICATION_FAILED.code(),
                "KMS authentication failed"
        );

        Result<Ciphertext, EncryptionError> result = service.encrypt(plaintext, context);

        assertThat(result.isFailure())
                .as("Encryption must fail when KMS authentication fails (plaintext='%s', context=%s)",
                        plaintext, context)
                .isTrue();

        assertThat(result.getValue())
                .as("No ciphertext value must be present when KMS authentication fails — "
                        + "this prevents data storage")
                .isEmpty();
    }

    /**
     * Property 26 (KMS timeout): For any plaintext and any bounded context,
     * when the KMS request times out, the encryption result SHALL be a failure and
     * SHALL NOT contain a ciphertext value.
     */
    @Property(tries = 200)
    @Label("Property 26: KMS timeout — encryption returns failure with no ciphertext value")
    void kmsTimeout_encryptionReturnsFailureWithNoCiphertextValue(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService service = buildServiceWithKeyError(
                EncryptionErrorCodes.KMS_TIMEOUT.code(),
                "KMS request timed out"
        );

        Result<Ciphertext, EncryptionError> result = service.encrypt(plaintext, context);

        assertThat(result.isFailure())
                .as("Encryption must fail when KMS times out (plaintext='%s', context=%s)",
                        plaintext, context)
                .isTrue();

        assertThat(result.getValue())
                .as("No ciphertext value must be present when KMS times out — "
                        + "this prevents data storage (Req 8.1)")
                .isEmpty();
    }

    /**
     * Property 26 (IV generation failure): For any plaintext and any bounded context,
     * when IV generation fails, the encryption result SHALL be a failure and
     * SHALL NOT contain a ciphertext value.
     */
    @Property(tries = 200)
    @Label("Property 26: IV generation failure — encryption returns failure with no ciphertext value")
    void ivGenerationFailure_encryptionReturnsFailureWithNoCiphertextValue(
            @ForAll("piiLikePlaintext") String plaintext,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService service = buildServiceWithFailingIVCounter();

        Result<Ciphertext, EncryptionError> result = service.encrypt(plaintext, context);

        assertThat(result.isFailure())
                .as("Encryption must fail when IV generation fails (plaintext='%s', context=%s)",
                        plaintext, context)
                .isTrue();

        assertThat(result.getValue())
                .as("No ciphertext value must be present when IV generation fails — "
                        + "this prevents data storage (Req 8.1)")
                .isEmpty();

        assertThat(result.getError())
                .as("A descriptive error must be present when IV generation fails (Req 8.1)")
                .isPresent();
    }

    /**
     * Property 26 (batch, KMS unavailable): For any list of plaintexts and any bounded context,
     * when the KMS is unavailable, the batch encryption result SHALL be a failure and
     * SHALL NOT contain any ciphertext values.
     */
    @Property(tries = 100)
    @Label("Property 26: Batch encryption — KMS unavailable returns failure with no ciphertext list")
    void batchEncryption_kmsUnavailable_returnsFailureWithNoCiphertextList(
            @ForAll("piiLikePlaintextList") List<String> plaintexts,
            @ForAll("boundedContext") BoundedContext context) {

        EncryptionService service = buildServiceWithKeyError(
                EncryptionErrorCodes.KMS_UNAVAILABLE.code(),
                "KMS is unavailable"
        );

        Result<List<Ciphertext>, EncryptionError> result = service.encryptBatch(plaintexts, context);

        assertThat(result.isFailure())
                .as("Batch encryption must fail when KMS is unavailable (context=%s, batchSize=%d)",
                        context, plaintexts.size())
                .isTrue();

        assertThat(result.getValue())
                .as("No ciphertext list must be present when batch encryption fails — "
                        + "this prevents data storage (Req 8.1)")
                .isEmpty();

        assertThat(result.getError())
                .as("A descriptive error must be present when batch encryption fails (Req 8.1)")
                .isPresent();
    }

    // =========================================================================
    // Arbitraries
    // =========================================================================

    /**
     * Generates PII-like plaintext values: emails, phone numbers, names, and IP addresses.
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

        return Arbitraries.oneOf(emails, phones, names, ipAddresses);
    }

    /**
     * Generates small lists of PII-like plaintext values for batch tests.
     */
    @Provide
    Arbitrary<List<String>> piiLikePlaintextList() {
        return piiLikePlaintext().list().ofMinSize(1).ofMaxSize(10);
    }

    /**
     * Generates arbitrary BoundedContext values covering all four contexts.
     */
    @Provide
    Arbitrary<BoundedContext> boundedContext() {
        return Arbitraries.of(BoundedContext.values());
    }

    // =========================================================================
    // Test infrastructure
    // =========================================================================

    /**
     * Builds an EncryptionService whose key manager always fails with the given error code.
     * This simulates KMS unavailability, key not found, authentication failure, and timeout.
     */
    private EncryptionService buildServiceWithKeyError(String errorCode, String message) {
        IKeyManager failingKeyManager = new AlwaysFailingKeyManager(errorCode, message);
        IAuditLogger noOpLogger = new NoOpAuditLogger();
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(failingKeyManager, "test-global-salt");
        return new EncryptionService(failingKeyManager, blindIndexService, noOpLogger, ivCounter);
    }

    /**
     * Builds an EncryptionService with a working key manager but a failing IV counter.
     * This simulates IV generation failures (e.g. entropy source unavailable).
     */
    private EncryptionService buildServiceWithFailingIVCounter() {
        UUID dekId = UUID.randomUUID();
        IKeyManager stubKeyManager = new StubKeyManager(dekId);
        IAuditLogger noOpLogger = new NoOpAuditLogger();
        IVCounter failingIVCounter = new AlwaysFailingIVCounter();
        BlindIndexService blindIndexService = new BlindIndexService(stubKeyManager, "test-global-salt");
        return new EncryptionService(stubKeyManager, blindIndexService, noOpLogger, failingIVCounter);
    }

    // =========================================================================
    // Test doubles
    // =========================================================================

    /**
     * Key manager that always returns a failure for {@code getActiveDEK} with the
     * specified error code. Simulates KMS unavailability, key not found, auth failure, etc.
     */
    private static final class AlwaysFailingKeyManager implements IKeyManager {

        private final String errorCode;
        private final String message;

        AlwaysFailingKeyManager(String errorCode, String message) {
            this.errorCode = errorCode;
            this.message = message;
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.failure(KeyError.of(errorCode, message));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            return Result.failure(KeyError.of(errorCode, message));
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
            return Result.failure(KeyError.of(errorCode, message));
        }
    }

    /**
     * IV counter that always fails on {@code generateIV}, simulating entropy source
     * unavailability or counter overflow conditions.
     */
    private static final class AlwaysFailingIVCounter implements IVCounter {

        @Override
        public Result<IV, IVCounterError> generateIV(UUID dekId) {
            return Result.failure(IVCounterError.invalidState("IV generation failed in test"));
        }

        @Override
        public Result<Unit, IVCounterError> persistState(UUID dekId) {
            return Result.success(Unit.unit());
        }

        @Override
        public Result<IVCounterState, IVCounterError> loadState(UUID dekId) {
            return Result.failure(IVCounterError.loadFailed(dekId.toString(), "not available in test"));
        }

        @Override
        public Result<Unit, IVCounterError> resetState(UUID dekId) {
            return Result.success(Unit.unit());
        }
    }

    /**
     * Minimal IKeyManager stub that always returns a fixed DEK for any context or key ID.
     * Used when testing IV counter failures (key manager must succeed for the test to reach IV generation).
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
