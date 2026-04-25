package dev.vibeafrika.pcm.infrastructure.encryption.integration;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.adapter.DatabaseEncryptionAdapter;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Blind indexing integration tests.
 *
 * <p>Tests:
 * <ul>
 *   <li>Blind index generation during persistence</li>
 *   <li>Searching by blind index</li>
 *   <li>Blind index with global and per-record salts</li>
 * </ul>
 */
@DisplayName("Blind Index Integration Tests")
class BlindIndexIntegrationTest {

    private static final String GLOBAL_SALT = "blind-index-integration-test-global-salt";

    private BlindIndexService blindIndexService;
    private EncryptionService encryptionService;
    private DatabaseEncryptionAdapter adapter;
    private StubKeyManager keyManager;

    @BeforeEach
    void setUp() {
        UUID dekId = UUID.randomUUID();
        keyManager = new StubKeyManager(dekId);
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        blindIndexService = new BlindIndexService(keyManager, GLOBAL_SALT);
        NoOpAuditLogger auditLogger = new NoOpAuditLogger();
        encryptionService = new EncryptionService(keyManager, blindIndexService, auditLogger, ivCounter);
        adapter = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.PROFILE);
    }

    // -------------------------------------------------------------------------
    // Blind index generation during persistence
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Blind index generation during persistence")
    class BlindIndexGenerationTests {

        @Test
        @DisplayName("Blind index is generated when entity is encrypted")
        void blindIndex_generatedDuringEncryption() {
            ProfileJpaEntity entity = profileEntity("alice@example.com");

            adapter.encryptEntity(entity);

            assertNotNull(entity.getHandleBlindIndex(),
                    "Blind index must be generated during encryption");
            assertFalse(entity.getHandleBlindIndex().isBlank(),
                    "Blind index must not be blank");
        }

        @Test
        @DisplayName("Blind index is a hex-encoded HMAC-SHA256 value")
        void blindIndex_isHexEncodedHmacSha256() {
            ProfileJpaEntity entity = profileEntity("bob@example.com");

            adapter.encryptEntity(entity);

            String blindIndex = entity.getHandleBlindIndex();
            assertNotNull(blindIndex);
            // HMAC-SHA256 produces 32 bytes = 64 hex characters
            assertEquals(64, blindIndex.length(),
                    "Blind index must be 64 hex characters (HMAC-SHA256 output)");
            assertTrue(blindIndex.matches("[0-9a-f]+"),
                    "Blind index must be lowercase hex");
        }

        @Test
        @DisplayName("Blind index is null when handle is null")
        void blindIndex_nullWhenHandleIsNull() {
            ProfileJpaEntity entity = profileEntity(null);

            adapter.encryptEntity(entity);

            assertNull(entity.getHandleBlindIndex(),
                    "Blind index must be null when handle is null");
        }

        @Test
        @DisplayName("Blind index is preserved after decryption")
        void blindIndex_preservedAfterDecryption() {
            ProfileJpaEntity entity = profileEntity("carol@example.com");
            adapter.encryptEntity(entity);
            String blindIndex = entity.getHandleBlindIndex();

            adapter.decryptEntity(entity);

            assertEquals(blindIndex, entity.getHandleBlindIndex(),
                    "Blind index must not be modified by decryption");
        }
    }

    // -------------------------------------------------------------------------
    // Searching by blind index
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Searching by blind index")
    class BlindIndexSearchTests {

        @Test
        @DisplayName("Same plaintext with same record salt produces same blind index (searchable)")
        void samePlaintextAndSalt_producesSameBlindIndex() {
            String plaintext = "dave@example.com";
            String recordSalt = "fixed-record-salt";

            Result<BlindIndex, EncryptionError> result1 = blindIndexService.generateBlindIndex(plaintext, recordSalt);
            Result<BlindIndex, EncryptionError> result2 = blindIndexService.generateBlindIndex(plaintext, recordSalt);

            assertTrue(result1.isSuccess());
            assertTrue(result2.isSuccess());
            assertEquals(result1.getValue().get().getValue(), result2.getValue().get().getValue(),
                    "Same plaintext and salt must produce same blind index (enables searching)");
        }

        @Test
        @DisplayName("Blind index verification succeeds for matching plaintext")
        void blindIndexVerification_succeedsForMatchingPlaintext() {
            String plaintext = "eve@example.com";
            String recordSalt = "verification-salt";

            Result<BlindIndex, EncryptionError> result = blindIndexService.generateBlindIndex(plaintext, recordSalt);
            assertTrue(result.isSuccess());
            BlindIndex blindIndex = result.getValue().get();

            boolean verified = blindIndexService.verifyBlindIndex(plaintext, recordSalt, blindIndex);
            assertTrue(verified, "Blind index verification must succeed for matching plaintext");
        }

        @Test
        @DisplayName("Blind index verification fails for non-matching plaintext")
        void blindIndexVerification_failsForNonMatchingPlaintext() {
            String plaintext = "frank@example.com";
            String wrongPlaintext = "wrong@example.com";
            String recordSalt = "verification-salt";

            Result<BlindIndex, EncryptionError> result = blindIndexService.generateBlindIndex(plaintext, recordSalt);
            assertTrue(result.isSuccess());
            BlindIndex blindIndex = result.getValue().get();

            boolean verified = blindIndexService.verifyBlindIndex(wrongPlaintext, recordSalt, blindIndex);
            assertFalse(verified, "Blind index verification must fail for non-matching plaintext");
        }

        @Test
        @DisplayName("Blind index search simulation: find entity by blind index")
        void blindIndexSearch_findsEntityByBlindIndex() {
            // Simulate a database of encrypted entities
            String targetEmail = "grace@example.com";
            String recordSalt = "grace-record-salt";

            // Generate blind index for the target
            Result<BlindIndex, EncryptionError> targetBlindIndexResult =
                    blindIndexService.generateBlindIndex(targetEmail, recordSalt);
            assertTrue(targetBlindIndexResult.isSuccess());
            String targetBlindIndex = targetBlindIndexResult.getValue().get().getValue();

            // Simulate stored entities with their blind indexes
            Map<String, String> blindIndexStore = new HashMap<>();
            blindIndexStore.put("user-1", blindIndexService.generateBlindIndex("other@example.com", "salt-1")
                    .getValue().get().getValue());
            blindIndexStore.put("user-2", targetBlindIndex);
            blindIndexStore.put("user-3", blindIndexService.generateBlindIndex("another@example.com", "salt-3")
                    .getValue().get().getValue());

            // Search by blind index
            String foundUserId = blindIndexStore.entrySet().stream()
                    .filter(e -> e.getValue().equals(targetBlindIndex))
                    .map(Map.Entry::getKey)
                    .findFirst()
                    .orElse(null);

            assertEquals("user-2", foundUserId,
                    "Searching by blind index must find the correct entity");
        }
    }

    // -------------------------------------------------------------------------
    // Blind index with global and per-record salts
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Blind index salt uniqueness")
    class BlindIndexSaltTests {

        @Test
        @DisplayName("Same plaintext with different per-record salts produces different blind indexes")
        void samePlaintext_differentRecordSalts_differentBlindIndexes() {
            String plaintext = "henry@example.com";

            Result<BlindIndex, EncryptionError> result1 =
                    blindIndexService.generateBlindIndex(plaintext, "salt-record-1");
            Result<BlindIndex, EncryptionError> result2 =
                    blindIndexService.generateBlindIndex(plaintext, "salt-record-2");

            assertTrue(result1.isSuccess());
            assertTrue(result2.isSuccess());
            assertNotEquals(result1.getValue().get().getValue(), result2.getValue().get().getValue(),
                    "Same plaintext with different per-record salts must produce different blind indexes");
        }

        @Test
        @DisplayName("Two entities with same handle produce different blind indexes (per-record salt)")
        void twoEntitiesWithSameHandle_differentBlindIndexes() {
            ProfileJpaEntity entity1 = profileEntity("iris@example.com");
            ProfileJpaEntity entity2 = profileEntity("iris@example.com");

            adapter.encryptEntity(entity1);
            adapter.encryptEntity(entity2);

            assertNotNull(entity1.getHandleBlindIndex());
            assertNotNull(entity2.getHandleBlindIndex());
            // Per-record salt is based on identity hash, so different entities get different blind indexes
            assertNotEquals(entity1.getHandleBlindIndex(), entity2.getHandleBlindIndex(),
                    "Two entities with same handle must have different blind indexes (per-record salt)");
        }

        @Test
        @DisplayName("Global salt is included in blind index computation")
        void globalSalt_includedInBlindIndexComputation() {
            // Two BlindIndexServices with different global salts should produce different blind indexes
            String plaintext = "jack@example.com";
            String recordSalt = "same-record-salt";

            BlindIndexService service1 = new BlindIndexService(keyManager, "global-salt-A");
            BlindIndexService service2 = new BlindIndexService(keyManager, "global-salt-B");

            Result<BlindIndex, EncryptionError> result1 = service1.generateBlindIndex(plaintext, recordSalt);
            Result<BlindIndex, EncryptionError> result2 = service2.generateBlindIndex(plaintext, recordSalt);

            assertTrue(result1.isSuccess());
            assertTrue(result2.isSuccess());
            assertNotEquals(result1.getValue().get().getValue(), result2.getValue().get().getValue(),
                    "Different global salts must produce different blind indexes");
        }

        @Test
        @DisplayName("Blind index is case-insensitive (normalized plaintext)")
        void blindIndex_caseInsensitive() {
            String lower = "kate@example.com";
            String upper = "KATE@EXAMPLE.COM";
            String mixed = "Kate@Example.Com";
            String recordSalt = "case-test-salt";

            Result<BlindIndex, EncryptionError> lowerResult = blindIndexService.generateBlindIndex(lower, recordSalt);
            Result<BlindIndex, EncryptionError> upperResult = blindIndexService.generateBlindIndex(upper, recordSalt);
            Result<BlindIndex, EncryptionError> mixedResult = blindIndexService.generateBlindIndex(mixed, recordSalt);

            assertTrue(lowerResult.isSuccess());
            assertTrue(upperResult.isSuccess());
            assertTrue(mixedResult.isSuccess());

            assertEquals(lowerResult.getValue().get().getValue(), upperResult.getValue().get().getValue(),
                    "Blind index must be case-insensitive (normalized)");
            assertEquals(lowerResult.getValue().get().getValue(), mixedResult.getValue().get().getValue(),
                    "Blind index must be case-insensitive (normalized)");
        }

        @Test
        @DisplayName("Blind index is trim-insensitive (normalized plaintext)")
        void blindIndex_trimInsensitive() {
            String withSpaces = "  leo@example.com  ";
            String trimmed = "leo@example.com";
            String recordSalt = "trim-test-salt";

            Result<BlindIndex, EncryptionError> spacesResult = blindIndexService.generateBlindIndex(withSpaces, recordSalt);
            Result<BlindIndex, EncryptionError> trimmedResult = blindIndexService.generateBlindIndex(trimmed, recordSalt);

            assertTrue(spacesResult.isSuccess());
            assertTrue(trimmedResult.isSuccess());
            assertEquals(spacesResult.getValue().get().getValue(), trimmedResult.getValue().get().getValue(),
                    "Blind index must be trim-insensitive (normalized)");
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static ProfileJpaEntity profileEntity(String handle) {
        ProfileJpaEntity entity = new ProfileJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setTenantId("blind-index-test-tenant");
        entity.setHandle(handle);
        return entity;
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

    static final class NoOpAuditLogger implements IAuditLogger {
        @SuppressWarnings({"unchecked", "rawtypes"})
        private static <E> Result<Void, E> voidOk() {
            return (Result<Void, E>) (Result) Result.success(Unit.unit());
        }

        @Override public Result<Void, AuditError> logEncryption(EncryptionEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logDecryption(DecryptionEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logKeyRotation(KeyRotationEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logSecurityEvent(SecurityEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logKeyAccess(KeyAccessEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent e) { return voidOk(); }
    }
}
