package dev.vibeafrika.pcm.infrastructure.encryption.adapter;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.*;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying that encryption/decryption works correctly for
 * {@link ProfileJpaEntity} via {@link DatabaseEncryptionAdapter}.
 *
 * <p>Validates Requirements :
 * <ul>
 *   <li>PII fields on Profile entities are encrypted before persistence</li>
 *   <li>Blind index is generated for the searchable {@code handle} field</li>
 * </ul>
 */
class ProfileEncryptionIntegrationTest {

    private DatabaseEncryptionAdapter adapter;

    @BeforeEach
    void setUp() {
        UUID dekId = UUID.randomUUID();
        StubKeyManager keyManager = new StubKeyManager(dekId);
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        EncryptionService encryptionService =
                new EncryptionService(keyManager, blindIndexService, new NoOpAuditLogger(), ivCounter);
        adapter = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.PROFILE);
    }

    // -------------------------------------------------------------------------
    // Handle field is encrypted before persistence
    // -------------------------------------------------------------------------

    @Test
    void encryptEntityEncryptsHandleField() {
        ProfileJpaEntity entity = profileEntity("alice");

        adapter.encryptEntity(entity);

        assertNotEquals("alice", entity.getHandle(),
                "handle must be encrypted – plaintext must not be stored");
    }

    @Test
    void encryptedHandleIsBase64Encoded() {
        ProfileJpaEntity entity = profileEntity("bob");

        adapter.encryptEntity(entity);

        assertDoesNotThrow(() -> java.util.Base64.getDecoder().decode(entity.getHandle()),
                "Encrypted handle must be valid Base64");
    }

    @Test
    void decryptEntityRestoresOriginalHandle() {
        String original = "carol";
        ProfileJpaEntity entity = profileEntity(original);

        adapter.encryptEntity(entity);
        adapter.decryptEntity(entity);

        assertEquals(original, entity.getHandle(),
                "handle must be restored to original value after decryption");
    }

    @Test
    void nullHandleIsLeftAsNull() {
        ProfileJpaEntity entity = profileEntity(null);

        adapter.encryptEntity(entity);

        assertNull(entity.getHandle(), "null handle must remain null after encryption");
    }

    @Test
    void nonPiiFieldsAreNotModified() {
        ProfileJpaEntity entity = profileEntity("dave");
        UUID id = UUID.randomUUID();
        entity.setId(id);
        entity.setTenantId("tenant-1");

        adapter.encryptEntity(entity);

        assertEquals(id, entity.getId(), "id must not be modified");
        assertEquals("tenant-1", entity.getTenantId(), "tenantId must not be modified");
    }

    // -------------------------------------------------------------------------
    // Blind index generated for searchable handle field
    // -------------------------------------------------------------------------

    @Test
    void encryptEntityGeneratesBlindIndexForHandle() {
        ProfileJpaEntity entity = profileEntity("eve");

        adapter.encryptEntity(entity);

        assertNotNull(entity.getHandleBlindIndex(),
                "handleBlindIndex must be populated after encryption");
        assertFalse(entity.getHandleBlindIndex().isBlank(),
                "handleBlindIndex must not be blank");
    }

    @Test
    void blindIndexIsNullWhenHandleIsNull() {
        ProfileJpaEntity entity = profileEntity(null);

        adapter.encryptEntity(entity);

        assertNull(entity.getHandleBlindIndex(),
                "handleBlindIndex must be null when handle is null");
    }

    @Test
    void roundTripPreservesHandleAndBlindIndex() {
        String original = "frank";
        ProfileJpaEntity entity = profileEntity(original);

        adapter.encryptEntity(entity);
        String blindIndex = entity.getHandleBlindIndex();
        assertNotNull(blindIndex, "blind index must be set after encryption");

        adapter.decryptEntity(entity);

        assertEquals(original, entity.getHandle(),
                "handle must be restored after round-trip");
        // Blind index column is not cleared on decryption – it persists in DB
        assertEquals(blindIndex, entity.getHandleBlindIndex(),
                "handleBlindIndex must not be modified by decryption");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static ProfileJpaEntity profileEntity(String handle) {
        ProfileJpaEntity entity = new ProfileJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setTenantId("test-tenant");
        entity.setHandle(handle);
        return entity;
    }

    // -------------------------------------------------------------------------
    // Test infrastructure stubs (same pattern as DatabaseEncryptionAdapterTest)
    // -------------------------------------------------------------------------

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
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            return Result.success(key);
        }
    }

    private static final class NoOpAuditLogger implements IAuditLogger {
        @SuppressWarnings({"unchecked", "rawtypes"})
        private static <E> Result<Void, E> voidOk() {
            return (Result<Void, E>) (Result) Result.success(Unit.unit());
        }

        @Override
        public Result<Void, AuditError> logEncryption(EncryptionEvent event) { return voidOk(); }
        @Override
        public Result<Void, AuditError> logDecryption(DecryptionEvent event) { return voidOk(); }
        @Override
        public Result<Void, AuditError> logKeyRotation(KeyRotationEvent event) { return voidOk(); }
        @Override
        public Result<Void, AuditError> logSecurityEvent(SecurityEvent event) { return voidOk(); }
        @Override
        public Result<Void, AuditError> logKeyAccess(KeyAccessEvent event) { return voidOk(); }
        @Override
        public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent event) { return voidOk(); }
    }
}
