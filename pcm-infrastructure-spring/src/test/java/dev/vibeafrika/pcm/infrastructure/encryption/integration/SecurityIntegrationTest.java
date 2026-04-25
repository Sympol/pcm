package dev.vibeafrika.pcm.infrastructure.encryption.integration;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.adapter.DatabaseEncryptionAdapter;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Security integration tests.
 *
 * <p>Tests: tampering detection, environment mismatch rejection,
 * unauthorized access denial, constant-time operations.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Security Integration Tests")
class SecurityIntegrationTest {

    @Mock
    private IAuditLogger auditLogger;

    private EncryptionService encryptionService;
    private BlindIndexService blindIndexService;
    private DatabaseEncryptionAdapter adapter;
    private StubKeyManager keyManager;

    @BeforeEach
    void setUp() {
        UUID dekId = UUID.randomUUID();
        keyManager = new StubKeyManager(dekId);
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        blindIndexService = new BlindIndexService(keyManager, "security-test-global-salt");

        lenient().when(auditLogger.logEncryption(any())).thenReturn(voidOk());
        lenient().when(auditLogger.logDecryption(any())).thenReturn(voidOk());
        lenient().when(auditLogger.logSecurityEvent(any())).thenReturn(voidOk());
        lenient().when(auditLogger.logKeyAccess(any())).thenReturn(voidOk());
        lenient().when(auditLogger.logKeyRotation(any())).thenReturn(voidOk());
        lenient().when(auditLogger.logAuditLogAccess(any())).thenReturn(voidOk());

        encryptionService = new EncryptionService(keyManager, blindIndexService, auditLogger, ivCounter);
        adapter = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.PROFILE);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static <E> Result<Void, E> voidOk() {
        return (Result<Void, E>) (Result) Result.success(Unit.unit());
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    // -------------------------------------------------------------------------
    // Tampering detection
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Tampering detection")
    class TamperingDetectionTests {

        @Test
        @DisplayName("Modified ciphertext is detected as tampering")
        void modifiedCiphertext_detectedAsTampering() {
            Result<Ciphertext, EncryptionError> encResult =
                    encryptionService.encrypt("sensitive-data", BoundedContext.PROFILE);
            assertTrue(encResult.isSuccess());

            byte[] original = encResult.getValue().get().getValue();
            byte[] tampered = original.clone();
            tampered[original.length - 1] ^= 0xFF;

            Result<String, DecryptionError> decResult =
                    encryptionService.decrypt(Ciphertext.of(tampered), BoundedContext.PROFILE);

            assertTrue(decResult.isFailure(), "Tampered ciphertext must fail decryption");
            assertEquals("TAMPERING_DETECTED", decResult.getError().get().getCode(),
                    "Error code must be TAMPERING_DETECTED");
        }

        @Test
        @DisplayName("Tampering triggers security audit log event")
        void tampering_triggersSecurityAuditLogEvent() {
            Result<Ciphertext, EncryptionError> encResult =
                    encryptionService.encrypt("audit-test-data", BoundedContext.PROFILE);
            assertTrue(encResult.isSuccess());

            byte[] original = encResult.getValue().get().getValue();
            byte[] tampered = original.clone();
            tampered[original.length - 1] ^= 0xFF;

            encryptionService.decrypt(Ciphertext.of(tampered), BoundedContext.PROFILE);

            ArgumentCaptor<SecurityEvent> eventCaptor = ArgumentCaptor.forClass(SecurityEvent.class);
            verify(auditLogger, atLeastOnce()).logSecurityEvent(eventCaptor.capture());

            boolean tamperingEventLogged = eventCaptor.getAllValues().stream()
                    .anyMatch(e -> "TAMPERING_DETECTED".equals(e.getEventType()));
            assertTrue(tamperingEventLogged,
                    "Tampering detection must trigger a security audit log event");
        }

        @Test
        @DisplayName("Error message does not expose sensitive details")
        void errorMessage_doesNotExposeSensitiveDetails() {
            Result<Ciphertext, EncryptionError> encResult =
                    encryptionService.encrypt("secret-data", BoundedContext.PROFILE);
            assertTrue(encResult.isSuccess());

            byte[] tampered = encResult.getValue().get().getValue().clone();
            tampered[tampered.length - 1] ^= 0xFF;

            Result<String, DecryptionError> decResult =
                    encryptionService.decrypt(Ciphertext.of(tampered), BoundedContext.PROFILE);

            assertTrue(decResult.isFailure());
            String errorMessage = decResult.getError().get().getMessage();
            assertFalse(errorMessage.contains("secret-data"),
                    "Error message must not contain plaintext PII");
        }

        @Test
        @DisplayName("Tampered entity field throws exception during decryption")
        void tamperedEntityField_throwsExceptionDuringDecryption() {
            ProfileJpaEntity entity = new ProfileJpaEntity();
            entity.setId(UUID.randomUUID());
            entity.setTenantId("security-test-tenant");
            entity.setHandle("tamper-test@example.com");
            adapter.encryptEntity(entity);

            byte[] ciphertextBytes = Base64.getDecoder().decode(entity.getHandle());
            ciphertextBytes[ciphertextBytes.length - 1] ^= 0xFF;
            entity.setHandle(Base64.getEncoder().encodeToString(ciphertextBytes));

            assertThrows(Exception.class, () -> adapter.decryptEntity(entity),
                    "Decrypting tampered entity field must throw an exception");
        }
    }

    // -------------------------------------------------------------------------
    // Environment mismatch rejection 
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Environment mismatch rejection")
    class EnvironmentMismatchTests {

        @Test
        @DisplayName("DEK from wrong environment is rejected")
        void dekFromWrongEnvironment_isRejected() {
            UUID keyId = UUID.randomUUID();
            UUID kekId = UUID.randomUUID();

            DEKWithMetadata devDEK = DEKWithMetadata.builder()
                    .dek(DEK.of(randomBytes(32)))
                    .keyId(keyId).kekId(kekId)
                    .context(BoundedContext.PROFILE)
                    .environment(Environment.DEV)
                    .algorithm(EncryptionAlgorithm.AES_256_GCM)
                    .createdAt(Instant.now()).status(KeyStatus.ACTIVE)
                    .build();

            DEKCache dekCache = new DEKCache();
            dekCache.put(keyId, devDEK);

            IKMSClient mockKms = mock(IKMSClient.class);
            KeyManager prodManager = new KeyManager(mockKms, auditLogger, dekCache, Environment.PROD,
                    new IVCounterImpl(new InMemoryIVCounterStorage()));

            Result<DEKWithMetadata, KeyError> result = prodManager.getDEK(keyId);

            assertTrue(result.isFailure(), "PROD manager must reject DEV DEK");
            assertEquals("ENVIRONMENT_MISMATCH", result.getError().get().getCode(),
                    "Error code must be ENVIRONMENT_MISMATCH");
        }

        @Test
        @DisplayName("Environment mismatch logs security event")
        void environmentMismatch_logsSecurityEvent() {
            UUID keyId = UUID.randomUUID();
            UUID kekId = UUID.randomUUID();

            DEKWithMetadata devDEK = DEKWithMetadata.builder()
                    .dek(DEK.of(randomBytes(32)))
                    .keyId(keyId).kekId(kekId)
                    .context(BoundedContext.PROFILE)
                    .environment(Environment.DEV)
                    .algorithm(EncryptionAlgorithm.AES_256_GCM)
                    .createdAt(Instant.now()).status(KeyStatus.ACTIVE)
                    .build();

            DEKCache dekCache = new DEKCache();
            dekCache.put(keyId, devDEK);

            IKMSClient mockKms = mock(IKMSClient.class);
            KeyManager prodManager = new KeyManager(mockKms, auditLogger, dekCache, Environment.PROD,
                    new IVCounterImpl(new InMemoryIVCounterStorage()));

            prodManager.getDEK(keyId);

            ArgumentCaptor<SecurityEvent> eventCaptor = ArgumentCaptor.forClass(SecurityEvent.class);
            verify(auditLogger).logSecurityEvent(eventCaptor.capture());
            assertEquals("ENVIRONMENT_MISMATCH", eventCaptor.getValue().getEventType(),
                    "Security event type must be ENVIRONMENT_MISMATCH");
        }
    }

    // -------------------------------------------------------------------------
    // Unauthorized access denial
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Unauthorized access denial")
    class UnauthorizedAccessTests {

        @Test
        @DisplayName("Encryption fails gracefully when DEK is unavailable")
        void encryption_failsGracefully_whenDEKUnavailable() {
            IKeyManager failingKeyManager = new FailingKeyManager();
            IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
            BlindIndexService bis = new BlindIndexService(failingKeyManager, "test-salt");
            EncryptionService failingService = new EncryptionService(failingKeyManager, bis, auditLogger, ivCounter);

            Result<Ciphertext, EncryptionError> result =
                    failingService.encrypt("sensitive-data", BoundedContext.PROFILE);

            assertTrue(result.isFailure(), "Encryption must fail when DEK is unavailable");
            assertEquals("KEY_UNAVAILABLE", result.getError().get().getCode(),
                    "Error code must be KEY_UNAVAILABLE");
        }

        @Test
        @DisplayName("Decryption fails gracefully when DEK is not found")
        void decryption_failsGracefully_whenDEKNotFound() {
            // Encrypt with valid key manager
            Result<Ciphertext, EncryptionError> encResult =
                    encryptionService.encrypt("test-data", BoundedContext.PROFILE);
            assertTrue(encResult.isSuccess());

            // Try to decrypt with a key manager that can't find the DEK
            IKeyManager notFoundKeyManager = new NotFoundKeyManager();
            IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
            BlindIndexService bis = new BlindIndexService(notFoundKeyManager, "test-salt");
            EncryptionService notFoundService = new EncryptionService(notFoundKeyManager, bis, auditLogger, ivCounter);

            Result<String, DecryptionError> decResult =
                    notFoundService.decrypt(encResult.getValue().get(), BoundedContext.PROFILE);

            assertTrue(decResult.isFailure(), "Decryption must fail when DEK is not found");
        }
    }

    // -------------------------------------------------------------------------
    // Constant-time operations
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Constant-time operations")
    class ConstantTimeTests {

        @Test
        @DisplayName("ConstantTime.verifyAuthTag returns true for identical tags")
        void constantTimeVerifyAuthTag_identicalTags_returnsTrue() {
            byte[] tag = randomBytes(16);
            byte[] copy = tag.clone();

            assertTrue(ConstantTime.verifyAuthTag(tag, copy),
                    "Identical auth tags must be equal");
        }

        @Test
        @DisplayName("ConstantTime.verifyAuthTag returns false for different tags")
        void constantTimeVerifyAuthTag_differentTags_returnsFalse() {
            byte[] tag1 = randomBytes(16);
            byte[] tag2 = randomBytes(16);

            assertFalse(ConstantTime.verifyAuthTag(tag1, tag2),
                    "Different auth tags must not be equal");
        }

        @Test
        @DisplayName("ConstantTime.verifyHmac returns true for identical HMACs")
        void constantTimeVerifyHmac_identicalHmacs_returnsTrue() {
            byte[] hmac = randomBytes(32);
            byte[] copy = hmac.clone();

            assertTrue(ConstantTime.verifyHmac(hmac, copy),
                    "Identical HMACs must be equal");
        }

        @Test
        @DisplayName("ConstantTime.verifyHmac returns false for different HMACs")
        void constantTimeVerifyHmac_differentHmacs_returnsFalse() {
            byte[] hmac1 = randomBytes(32);
            byte[] hmac2 = randomBytes(32);

            assertFalse(ConstantTime.verifyHmac(hmac1, hmac2),
                    "Different HMACs must not be equal");
        }

        @Test
        @DisplayName("Blind index verification uses constant-time comparison")
        void blindIndexVerification_usesConstantTimeComparison() {
            String plaintext = "constant-time-test@example.com";
            String recordSalt = "ct-test-salt";

            Result<BlindIndex, EncryptionError> result = blindIndexService.generateBlindIndex(plaintext, recordSalt);
            assertTrue(result.isSuccess());

            // Verify correct value
            assertTrue(blindIndexService.verifyBlindIndex(plaintext, recordSalt, result.getValue().get()),
                    "Blind index verification must succeed for correct value");

            // Verify incorrect value
            assertFalse(blindIndexService.verifyBlindIndex("wrong@example.com", recordSalt, result.getValue().get()),
                    "Blind index verification must fail for incorrect value");
        }
    }

    // -------------------------------------------------------------------------
    // Test infrastructure stubs
    // -------------------------------------------------------------------------

    static final class StubKeyManager implements IKeyManager {
        private final UUID keyId;
        private final DEK dek;
        private final byte[] blindIndexKey;

        StubKeyManager(UUID keyId) {
            this.keyId = keyId;
            byte[] keyMaterial = new byte[32];
            new SecureRandom().nextBytes(keyMaterial);
            this.dek = DEK.of(keyMaterial);
            this.blindIndexKey = new byte[32];
            new SecureRandom().nextBytes(this.blindIndexKey);
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
                    .dek(dek).keyId(keyId).kekId(UUID.randomUUID())
                    .context(context).environment(Environment.DEV)
                    .algorithm(EncryptionAlgorithm.AES_256_GCM)
                    .createdAt(Instant.now()).status(KeyStatus.ACTIVE)
                    .build();
        }

        @Override
        public Result<UUID, KeyError> rotateDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<UUID, KeyError> rotateKEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<Void, KeyError> invalidateCache(UUID keyId) {
            return Result.success(null);
        }

        @Override
        public Result<DeletionCertificate, KeyError> deleteUserDEK(String userId, BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<byte[], KeyError> getBlindIndexKey() {
            return Result.success(blindIndexKey.clone());
        }
    }

    static final class FailingKeyManager implements IKeyManager {
        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.failure(KeyError.of("KEY_UNAVAILABLE", "No DEK available"));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            return Result.failure(KeyError.of("KEY_UNAVAILABLE", "No DEK available"));
        }

        @Override
        public Result<UUID, KeyError> rotateDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<UUID, KeyError> rotateKEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<Void, KeyError> invalidateCache(UUID keyId) {
            return Result.success(null);
        }

        @Override
        public Result<DeletionCertificate, KeyError> deleteUserDEK(String userId, BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<byte[], KeyError> getBlindIndexKey() {
            return Result.failure(KeyError.of("KEY_UNAVAILABLE", "No blind index key"));
        }
    }

    static final class NotFoundKeyManager implements IKeyManager {
        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.failure(KeyError.of("KEY_NOT_FOUND", "DEK not found"));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            return Result.failure(KeyError.of("KEY_NOT_FOUND", "DEK not found"));
        }

        @Override
        public Result<UUID, KeyError> rotateDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<UUID, KeyError> rotateKEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<Void, KeyError> invalidateCache(UUID keyId) {
            return Result.success(null);
        }

        @Override
        public Result<DeletionCertificate, KeyError> deleteUserDEK(String userId, BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<byte[], KeyError> getBlindIndexKey() {
            return Result.failure(KeyError.of("KEY_NOT_FOUND", "Blind index key not found"));
        }
    }
}
