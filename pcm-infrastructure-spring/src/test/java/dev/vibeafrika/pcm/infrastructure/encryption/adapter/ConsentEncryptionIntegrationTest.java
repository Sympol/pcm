package dev.vibeafrika.pcm.infrastructure.encryption.adapter;

import dev.vibeafrika.pcm.consent.domain.model.ConsentStatus;
import dev.vibeafrika.pcm.consent.infrastructure.persistence.entity.ConsentJpaEntity;
import dev.vibeafrika.pcm.consent.infrastructure.persistence.listener.ConsentEncryptionEntityListener;
import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests verifying that the Consent context encryption integration is wired correctly.
 *
 * <p>Validates Requirements:
 * <ul>
 *   <li>Consent context uses {@link BoundedContext#CONSENT} for encryption operations</li>
 *   <li>Entities without PII fields are handled gracefully (no-op)</li>
 * </ul>
 */
class ConsentEncryptionIntegrationTest {

    private DatabaseEncryptionAdapter adapter;

    @BeforeEach
    void setUp() {
        UUID dekId = UUID.randomUUID();
        StubKeyManager keyManager = new StubKeyManager(dekId);
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        EncryptionService encryptionService =
                new EncryptionService(keyManager, blindIndexService, new NoOpAuditLogger(), ivCounter);
        adapter = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.CONSENT);
    }

    // -------------------------------------------------------------------------
    // Adapter uses BoundedContext.CONSENT
    // -------------------------------------------------------------------------

    @Test
    void adapterIsCreatedWithConsentBoundedContext() {
        // Verify the adapter can be constructed with CONSENT context without error
        UUID dekId = UUID.randomUUID();
        StubKeyManager keyManager = new StubKeyManager(dekId);
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(keyManager, "test-global-salt");
        EncryptionService encryptionService =
                new EncryptionService(keyManager, blindIndexService, new NoOpAuditLogger(), ivCounter);

        assertDoesNotThrow(() ->
                new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.CONSENT),
                "DatabaseEncryptionAdapter must be constructable with BoundedContext.CONSENT");
    }

    // -------------------------------------------------------------------------
    // ConsentJpaEntity (no PII fields) is handled gracefully
    // -------------------------------------------------------------------------

    @Test
    void encryptEntityIsNoOpForConsentJpaEntity() {
        ConsentJpaEntity entity = consentEntity();
        String purposeBefore = entity.getPurpose();
        String scopeBefore = entity.getScope();
        String tenantBefore = entity.getTenantId();

        // Should not throw and should not modify non-PII fields
        assertDoesNotThrow(() -> adapter.encryptEntity(entity),
                "encryptEntity must not throw for ConsentJpaEntity with no @EncryptedField fields");

        assertEquals(purposeBefore, entity.getPurpose(), "purpose must not be modified (not PII)");
        assertEquals(scopeBefore, entity.getScope(), "scope must not be modified (not PII)");
        assertEquals(tenantBefore, entity.getTenantId(), "tenantId must not be modified (not PII)");
    }

    @Test
    void decryptEntityIsNoOpForConsentJpaEntity() {
        ConsentJpaEntity entity = consentEntity();
        String purposeBefore = entity.getPurpose();
        String scopeBefore = entity.getScope();

        assertDoesNotThrow(() -> adapter.decryptEntity(entity),
                "decryptEntity must not throw for ConsentJpaEntity with no @EncryptedField fields");

        assertEquals(purposeBefore, entity.getPurpose(), "purpose must not be modified");
        assertEquals(scopeBefore, entity.getScope(), "scope must not be modified");
    }

    @Test
    void roundTripEncryptDecryptLeavesConsentEntityUnchanged() {
        ConsentJpaEntity entity = consentEntity();
        UUID idBefore = entity.getId();
        UUID profileIdBefore = entity.getProfileId();
        String purposeBefore = entity.getPurpose();
        String scopeBefore = entity.getScope();
        ConsentStatus statusBefore = entity.getStatus();

        adapter.encryptEntity(entity);
        adapter.decryptEntity(entity);

        assertEquals(idBefore, entity.getId(), "id must be unchanged after round-trip");
        assertEquals(profileIdBefore, entity.getProfileId(), "profileId must be unchanged after round-trip");
        assertEquals(purposeBefore, entity.getPurpose(), "purpose must be unchanged after round-trip");
        assertEquals(scopeBefore, entity.getScope(), "scope must be unchanged after round-trip");
        assertEquals(statusBefore, entity.getStatus(), "status must be unchanged after round-trip");
    }

    @Test
    void consentEncryptionEntityListenerDelegatesAreWiredCorrectly() {
        // Wire the static delegates (simulating what DatabaseEncryptionAdapterConfiguration does)
        ConsentEncryptionEntityListener.setDelegates(
                adapter::encryptEntity,
                adapter::decryptEntity);

        ConsentEncryptionEntityListener listener = new ConsentEncryptionEntityListener();
        ConsentJpaEntity entity = consentEntity();

        // Listener callbacks must not throw for entities with no PII fields
        assertDoesNotThrow(() -> listener.prePersist(entity),
                "prePersist must not throw for ConsentJpaEntity");
        assertDoesNotThrow(() -> listener.preUpdate(entity),
                "preUpdate must not throw for ConsentJpaEntity");
        assertDoesNotThrow(() -> listener.postLoad(entity),
                "postLoad must not throw for ConsentJpaEntity");
    }

    @Test
    void consentEncryptionEntityListenerIsNoOpWhenDelegatesNotSet() {
        // Reset delegates to simulate unconfigured state
        ConsentEncryptionEntityListener.setDelegates(null, null);

        ConsentEncryptionEntityListener listener = new ConsentEncryptionEntityListener();
        ConsentJpaEntity entity = consentEntity();

        assertDoesNotThrow(() -> listener.prePersist(entity),
                "prePersist must not throw when delegates are null");
        assertDoesNotThrow(() -> listener.preUpdate(entity),
                "preUpdate must not throw when delegates are null");
        assertDoesNotThrow(() -> listener.postLoad(entity),
                "postLoad must not throw when delegates are null");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static ConsentJpaEntity consentEntity() {
        ConsentJpaEntity entity = new ConsentJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setProfileId(UUID.randomUUID());
        entity.setTenantId("test-tenant");
        entity.setPurpose("marketing");
        entity.setScope("email");
        entity.setStatus(ConsentStatus.GRANTED);
        return entity;
    }

    // -------------------------------------------------------------------------
    // Test infrastructure stubs (same pattern as ProfileEncryptionIntegrationTest)
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
            return Result.success(buildMetadata(BoundedContext.CONSENT));
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
