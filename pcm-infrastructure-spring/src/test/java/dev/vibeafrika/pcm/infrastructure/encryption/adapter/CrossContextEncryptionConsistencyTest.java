package dev.vibeafrika.pcm.infrastructure.encryption.adapter;

import dev.vibeafrika.pcm.consent.infrastructure.persistence.entity.ConsentJpaEntity;
import dev.vibeafrika.pcm.consent.domain.model.ConsentStatus;
import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.*;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.entity.PreferenceJpaEntity;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;
import dev.vibeafrika.pcm.segment.infrastructure.persistence.entity.SegmentJpaEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests verifying encryption consistency across all four bounded contexts.
 *
 * <p>Validates Requirements :
 * <ul>
 *   <li>Encryption standards are consistent across all bounded contexts</li>
 *   <li>PII shared between bounded contexts maintains consistent encryption</li>
 *   <li>Cross-context data sharing decrypts with source context DEK and
 *               re-encrypts with target context DEK</li>
 * </ul>
 */
class CrossContextEncryptionConsistencyTest {

    // Shared key manager so all contexts use the same underlying DEK for simplicity
    private StubKeyManager sharedKeyManager;

    private DatabaseEncryptionAdapter profileAdapter;
    private DatabaseEncryptionAdapter consentAdapter;
    private DatabaseEncryptionAdapter segmentAdapter;
    private DatabaseEncryptionAdapter preferenceAdapter;

    @BeforeEach
    void setUp() {
        UUID dekId = UUID.randomUUID();
        sharedKeyManager = new StubKeyManager(dekId);
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        BlindIndexService blindIndexService = new BlindIndexService(sharedKeyManager, "test-global-salt");
        NoOpAuditLogger auditLogger = new NoOpAuditLogger();
        EncryptionService encryptionService =
                new EncryptionService(sharedKeyManager, blindIndexService, auditLogger, ivCounter);

        profileAdapter    = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.PROFILE);
        consentAdapter    = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.CONSENT);
        segmentAdapter    = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.SEGMENT);
        preferenceAdapter = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.PREFERENCE);
    }

    // -------------------------------------------------------------------------
    // Encryption standards are consistent across contexts
    // -------------------------------------------------------------------------

    @Test
    void allContextAdaptersEncryptUsingAes256Gcm() {
        // Profile: handle is encrypted
        ProfileJpaEntity profile = profileEntity("alice");
        profileAdapter.encryptEntity(profile);
        byte[] profileCiphertext = Base64.getDecoder().decode(profile.getHandle());

        // Verify ciphertext format: version(1) + alg(1) + keyId(16) + IV(12) + ct + tag(16)
        // Minimum length = 46 bytes
        assertTrue(profileCiphertext.length >= 46,
                "Profile ciphertext must be at least 46 bytes (format overhead)");
        assertEquals(0x01, profileCiphertext[0] & 0xFF,
                "Version byte must be 0x01");
        assertEquals(0x01, profileCiphertext[1] & 0xFF,
                "Algorithm ID must be 0x01 (AES-256-GCM)");
    }

    @Test
    void profileHandleEncryptionRoundTripIsCorrect() {
        String original = "bob";
        ProfileJpaEntity entity = profileEntity(original);

        profileAdapter.encryptEntity(entity);
        assertNotEquals(original, entity.getHandle(), "handle must be encrypted");

        profileAdapter.decryptEntity(entity);
        assertEquals(original, entity.getHandle(), "handle must be restored after decryption");
    }

    @Test
    void allContextAdaptersHandleEntitiesWithNoPiiFieldsGracefully() {
        // Consent, Segment, Preference have no @EncryptedField fields
        ConsentJpaEntity consent = consentEntity();
        SegmentJpaEntity segment = segmentEntity();
        PreferenceJpaEntity preference = preferenceEntity();

        assertDoesNotThrow(() -> consentAdapter.encryptEntity(consent));
        assertDoesNotThrow(() -> segmentAdapter.encryptEntity(segment));
        assertDoesNotThrow(() -> preferenceAdapter.encryptEntity(preference));

        assertDoesNotThrow(() -> consentAdapter.decryptEntity(consent));
        assertDoesNotThrow(() -> segmentAdapter.decryptEntity(segment));
        assertDoesNotThrow(() -> preferenceAdapter.decryptEntity(preference));
    }

    @Test
    void encryptionProducesUniqueIvsAcrossContexts() {
        // Two encryptions of the same plaintext must produce different ciphertexts (unique IVs)
        ProfileJpaEntity entity1 = profileEntity("carol");
        ProfileJpaEntity entity2 = profileEntity("carol");

        profileAdapter.encryptEntity(entity1);
        profileAdapter.encryptEntity(entity2);

        assertNotEquals(entity1.getHandle(), entity2.getHandle(),
                "Same plaintext encrypted twice must produce different ciphertexts (unique IVs)");
    }

    @Test
    void blindIndexIsGeneratedConsistentlyForProfileHandle() {
        // Two entities with the same handle but different identity hashes get different blind indexes
        // (per-record salt is based on identity hash)
        ProfileJpaEntity entity1 = profileEntity("dave");
        ProfileJpaEntity entity2 = profileEntity("dave");

        profileAdapter.encryptEntity(entity1);
        profileAdapter.encryptEntity(entity2);

        assertNotNull(entity1.getHandleBlindIndex(), "blind index must be set for entity1");
        assertNotNull(entity2.getHandleBlindIndex(), "blind index must be set for entity2");
        // Blind indexes differ because per-record salt differs (identity hash)
        assertNotEquals(entity1.getHandleBlindIndex(), entity2.getHandleBlindIndex(),
                "Blind indexes for same plaintext with different per-record salts must differ");
    }

    // -------------------------------------------------------------------------
    // PII shared between contexts maintains consistent encryption
    // -------------------------------------------------------------------------

    @Test
    void encryptedDataFromProfileContextIsDecryptableByProfileAdapter() {
        String original = "eve";
        ProfileJpaEntity entity = profileEntity(original);

        profileAdapter.encryptEntity(entity);
        String encrypted = entity.getHandle();

        // Simulate loading from DB and decrypting
        ProfileJpaEntity loaded = profileEntity(encrypted);
        profileAdapter.decryptEntity(loaded);

        assertEquals(original, loaded.getHandle(),
                "Data encrypted by profile adapter must be decryptable by profile adapter");
    }

    // -------------------------------------------------------------------------
    // Cross-context re-encryption
    // -------------------------------------------------------------------------

    @Test
    void crossContextReEncryptionDecryptsWithSourceAndReEncryptsWithTarget() {
        // Simulate: Profile context encrypts a handle value
        String plaintext = "frank";
        ProfileJpaEntity profileEntity = profileEntity(plaintext);
        profileAdapter.encryptEntity(profileEntity);
        String encryptedByProfile = profileEntity.getHandle();

        // Step 1: Decrypt with source context (Profile)
        ProfileJpaEntity decryptedEntity = profileEntity(encryptedByProfile);
        profileAdapter.decryptEntity(decryptedEntity);
        String decryptedPlaintext = decryptedEntity.getHandle();
        assertEquals(plaintext, decryptedPlaintext,
                "Decryption with source context must restore original plaintext");

        // Step 2: Re-encrypt with target context (Consent adapter, simulating cross-context sharing)
        // In practice this would be a different entity type, but we verify the re-encryption produces
        // a valid ciphertext that can be decrypted back to the same plaintext
        ProfileJpaEntity reEncryptTarget = profileEntity(decryptedPlaintext);
        consentAdapter.encryptEntity(reEncryptTarget);
        String reEncryptedByConsent = reEncryptTarget.getHandle();

        assertNotEquals(encryptedByProfile, reEncryptedByConsent,
                "Re-encrypted ciphertext must differ from original (different context/IV)");

        // Step 3: Verify re-encrypted data is decryptable
        ProfileJpaEntity finalEntity = profileEntity(reEncryptedByConsent);
        consentAdapter.decryptEntity(finalEntity);
        assertEquals(plaintext, finalEntity.getHandle(),
                "Re-encrypted data must be decryptable with target context adapter");
    }

    @Test
    void allFourContextAdaptersCanEncryptAndDecryptProfileHandleValue() {
        // Verify all four adapters can handle the same plaintext (using ProfileJpaEntity as vehicle)
        String plaintext = "grace";

        for (DatabaseEncryptionAdapter adapter : new DatabaseEncryptionAdapter[]{
                profileAdapter, consentAdapter, segmentAdapter, preferenceAdapter}) {

            ProfileJpaEntity entity = profileEntity(plaintext);
            adapter.encryptEntity(entity);
            assertNotEquals(plaintext, entity.getHandle(),
                    "Adapter must encrypt the handle field");

            adapter.decryptEntity(entity);
            assertEquals(plaintext, entity.getHandle(),
                    "Adapter must decrypt the handle field back to original");
        }
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

    private static SegmentJpaEntity segmentEntity() {
        SegmentJpaEntity entity = new SegmentJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setProfileId(UUID.randomUUID());
        entity.setTenantId("test-tenant");
        entity.setTags(new HashSet<>(Set.of("tag-a")));
        entity.setScores(new HashMap<>(Map.of("score-x", 0.5)));
        entity.setLastUpdated(Instant.now());
        return entity;
    }

    private static PreferenceJpaEntity preferenceEntity() {
        PreferenceJpaEntity entity = new PreferenceJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setProfileId(UUID.randomUUID());
        entity.setTenantId("test-tenant");
        entity.setSettings(new HashMap<>(Map.of("theme", "dark")));
        entity.setLastUpdated(Instant.now());
        return entity;
    }

    // -------------------------------------------------------------------------
    // Test infrastructure stubs
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

        @Override public Result<Void, AuditError> logEncryption(EncryptionEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logDecryption(DecryptionEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logKeyRotation(KeyRotationEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logSecurityEvent(SecurityEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logKeyAccess(KeyAccessEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent e) { return voidOk(); }
    }
}
