package dev.vibeafrika.pcm.infrastructure.encryption.adapter;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.*;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.entity.PreferenceJpaEntity;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.listener.PreferenceEncryptionEntityListener;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying that the Preference context encryption integration is wired correctly.
 *
 * <p>Validates Requirements :
 * <ul>
 *   <li>Preference context uses {@link BoundedContext#PREFERENCE} for encryption operations</li>
 *   <li>Entities without PII fields are handled gracefully (no-op)</li>
 * </ul>
 */
class PreferenceEncryptionIntegrationTest {

    private DatabaseEncryptionAdapter adapter;

    @BeforeEach
    void setUp() {
        UUID dekId = UUID.randomUUID();
        StubKeyManager keyManager = new StubKeyManager(dekId);
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        EncryptionService encryptionService =
                new EncryptionService(keyManager, blindIndexService, new NoOpAuditLogger(), ivCounter);
        adapter = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.PREFERENCE);
    }

    @Test
    void adapterIsCreatedWithPreferenceBoundedContext() {
        UUID dekId = UUID.randomUUID();
        StubKeyManager keyManager = new StubKeyManager(dekId);
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        EncryptionService encryptionService =
                new EncryptionService(keyManager, blindIndexService, new NoOpAuditLogger(), ivCounter);

        assertDoesNotThrow(() ->
                new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.PREFERENCE),
                "DatabaseEncryptionAdapter must be constructable with BoundedContext.PREFERENCE");
    }

    @Test
    void encryptEntityIsNoOpForPreferenceJpaEntity() {
        PreferenceJpaEntity entity = preferenceEntity();
        String tenantBefore = entity.getTenantId();
        UUID profileIdBefore = entity.getProfileId();
        Map<String, String> settingsBefore = new HashMap<>(entity.getSettings());

        assertDoesNotThrow(() -> adapter.encryptEntity(entity),
                "encryptEntity must not throw for PreferenceJpaEntity with no @EncryptedField fields");

        assertEquals(tenantBefore, entity.getTenantId(), "tenantId must not be modified (not PII)");
        assertEquals(profileIdBefore, entity.getProfileId(), "profileId must not be modified (not PII)");
        assertEquals(settingsBefore, entity.getSettings(), "settings must not be modified");
    }

    @Test
    void decryptEntityIsNoOpForPreferenceJpaEntity() {
        PreferenceJpaEntity entity = preferenceEntity();
        String tenantBefore = entity.getTenantId();
        Map<String, String> settingsBefore = new HashMap<>(entity.getSettings());

        assertDoesNotThrow(() -> adapter.decryptEntity(entity),
                "decryptEntity must not throw for PreferenceJpaEntity with no @EncryptedField fields");

        assertEquals(tenantBefore, entity.getTenantId(), "tenantId must not be modified");
        assertEquals(settingsBefore, entity.getSettings(), "settings must not be modified");
    }

    @Test
    void roundTripEncryptDecryptLeavesPreferenceEntityUnchanged() {
        PreferenceJpaEntity entity = preferenceEntity();
        UUID idBefore = entity.getId();
        UUID profileIdBefore = entity.getProfileId();
        String tenantBefore = entity.getTenantId();
        Map<String, String> settingsBefore = new HashMap<>(entity.getSettings());

        adapter.encryptEntity(entity);
        adapter.decryptEntity(entity);

        assertEquals(idBefore, entity.getId(), "id must be unchanged after round-trip");
        assertEquals(profileIdBefore, entity.getProfileId(), "profileId must be unchanged after round-trip");
        assertEquals(tenantBefore, entity.getTenantId(), "tenantId must be unchanged after round-trip");
        assertEquals(settingsBefore, entity.getSettings(), "settings must be unchanged after round-trip");
    }

    @Test
    void preferenceEncryptionEntityListenerDelegatesAreWiredCorrectly() {
        PreferenceEncryptionEntityListener.setDelegates(
                adapter::encryptEntity,
                adapter::decryptEntity);

        PreferenceEncryptionEntityListener listener = new PreferenceEncryptionEntityListener();
        PreferenceJpaEntity entity = preferenceEntity();

        assertDoesNotThrow(() -> listener.prePersist(entity), "prePersist must not throw");
        assertDoesNotThrow(() -> listener.preUpdate(entity), "preUpdate must not throw");
        assertDoesNotThrow(() -> listener.postLoad(entity), "postLoad must not throw");
    }

    @Test
    void preferenceEncryptionEntityListenerIsNoOpWhenDelegatesNotSet() {
        PreferenceEncryptionEntityListener.setDelegates(null, null);

        PreferenceEncryptionEntityListener listener = new PreferenceEncryptionEntityListener();
        PreferenceJpaEntity entity = preferenceEntity();

        assertDoesNotThrow(() -> listener.prePersist(entity), "prePersist must not throw when delegates null");
        assertDoesNotThrow(() -> listener.preUpdate(entity), "preUpdate must not throw when delegates null");
        assertDoesNotThrow(() -> listener.postLoad(entity), "postLoad must not throw when delegates null");
    }

    private static PreferenceJpaEntity preferenceEntity() {
        PreferenceJpaEntity entity = new PreferenceJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setProfileId(UUID.randomUUID());
        entity.setTenantId("test-tenant");
        entity.setSettings(new HashMap<>(Map.of("theme", "dark", "language", "en")));
        entity.setLastUpdated(Instant.now());
        return entity;
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
            return Result.success(buildMetadata(BoundedContext.PREFERENCE));
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

        @Override public Result<Void, AuditError> logEncryption(EncryptionEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logDecryption(DecryptionEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logKeyRotation(KeyRotationEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logSecurityEvent(SecurityEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logKeyAccess(KeyAccessEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent e) { return voidOk(); }
    }
}
