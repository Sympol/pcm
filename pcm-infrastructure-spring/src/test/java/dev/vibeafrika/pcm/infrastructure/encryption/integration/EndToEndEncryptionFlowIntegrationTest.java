package dev.vibeafrika.pcm.infrastructure.encryption.integration;

import dev.vibeafrika.pcm.consent.domain.model.ConsentStatus;
import dev.vibeafrika.pcm.consent.infrastructure.persistence.entity.ConsentJpaEntity;
import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.adapter.DatabaseEncryptionAdapter;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.entity.PreferenceJpaEntity;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;
import dev.vibeafrika.pcm.segment.infrastructure.persistence.entity.SegmentJpaEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end integration tests for the complete encryption flow:
 * encrypt → persist (simulate) → retrieve (simulate) → decrypt.
 *
 * <p>Tests all four bounded contexts (Profile, Consent, Segment, Preference)
 * and all PII field types.
 */
@DisplayName("End-to-End Encryption Flow Integration Tests")
class EndToEndEncryptionFlowIntegrationTest {

    private EncryptionService encryptionService;
    private BlindIndexService blindIndexService;
    private DatabaseEncryptionAdapter profileAdapter;
    private DatabaseEncryptionAdapter consentAdapter;
    private DatabaseEncryptionAdapter segmentAdapter;
    private DatabaseEncryptionAdapter preferenceAdapter;
    private StubKeyManager keyManager;

    @BeforeEach
    void setUp() {
        UUID dekId = UUID.randomUUID();
        keyManager = new StubKeyManager(dekId);
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        blindIndexService = new BlindIndexService(keyManager, "integration-test-global-salt");
        NoOpAuditLogger auditLogger = new NoOpAuditLogger();
        encryptionService = new EncryptionService(keyManager, blindIndexService, auditLogger, ivCounter);

        profileAdapter = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.PROFILE);
        consentAdapter = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.CONSENT);
        segmentAdapter = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.SEGMENT);
        preferenceAdapter = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.PREFERENCE);
    }

    // -------------------------------------------------------------------------
    // Complete flow: encrypt → persist → retrieve → decrypt
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Complete encrypt-persist-retrieve-decrypt flow")
    class CompleteFlowTests {

        @Test
        @DisplayName("Profile handle: encrypt then decrypt restores original value")
        void profileHandle_encryptThenDecrypt_restoresOriginal() {
            String original = "alice@example.com";
            ProfileJpaEntity entity = profileEntity(original);

            // Simulate pre-persist (encrypt)
            profileAdapter.encryptEntity(entity);
            String encrypted = entity.getHandle();
            assertNotEquals(original, encrypted, "Handle must be encrypted before persistence");

            // Simulate post-load (decrypt)
            ProfileJpaEntity loaded = profileEntity(encrypted);
            profileAdapter.decryptEntity(loaded);

            assertEquals(original, loaded.getHandle(), "Handle must be restored after decryption");
        }

        @Test
        @DisplayName("Encrypted ciphertext is Base64-encoded and has correct format overhead")
        void encryptedHandle_isBase64WithCorrectOverhead() {
            ProfileJpaEntity entity = profileEntity("bob@example.com");
            profileAdapter.encryptEntity(entity);

            byte[] ciphertextBytes = Base64.getDecoder().decode(entity.getHandle());
            // Minimum: version(1) + alg(1) + keyId(16) + IV(12) + tag(16) = 46 bytes
            assertTrue(ciphertextBytes.length >= 46,
                    "Ciphertext must be at least 46 bytes (format overhead)");
            assertEquals(0x01, ciphertextBytes[0] & 0xFF, "Version byte must be 0x01");
            assertEquals(0x01, ciphertextBytes[1] & 0xFF, "Algorithm ID must be 0x01 (AES-256-GCM)");
        }

        @Test
        @DisplayName("Two encryptions of same plaintext produce different ciphertexts (unique IVs)")
        void twoEncryptionsOfSamePlaintext_produceDifferentCiphertexts() {
            ProfileJpaEntity e1 = profileEntity("carol@example.com");
            ProfileJpaEntity e2 = profileEntity("carol@example.com");

            profileAdapter.encryptEntity(e1);
            profileAdapter.encryptEntity(e2);

            assertNotEquals(e1.getHandle(), e2.getHandle(),
                    "Same plaintext encrypted twice must produce different ciphertexts (unique IVs)");
        }

        @Test
        @DisplayName("Null PII fields are left as null after encryption")
        void nullPiiField_remainsNull_afterEncryption() {
            ProfileJpaEntity entity = profileEntity(null);
            profileAdapter.encryptEntity(entity);
            assertNull(entity.getHandle(), "Null handle must remain null after encryption");
        }

        @Test
        @DisplayName("Non-PII fields are not modified during encryption")
        void nonPiiFields_notModified_duringEncryption() {
            ProfileJpaEntity entity = profileEntity("dave@example.com");
            UUID id = UUID.randomUUID();
            entity.setId(id);
            entity.setTenantId("tenant-integration");

            profileAdapter.encryptEntity(entity);

            assertEquals(id, entity.getId(), "ID must not be modified");
            assertEquals("tenant-integration", entity.getTenantId(), "TenantId must not be modified");
        }
    }

    // -------------------------------------------------------------------------
    // All bounded contexts
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("All bounded contexts encryption")
    class AllBoundedContextsTests {

        @Test
        @DisplayName("Profile context: handle field is encrypted and decryptable")
        void profileContext_handleEncryptedAndDecryptable() {
            String original = "profile-user";
            ProfileJpaEntity entity = profileEntity(original);

            profileAdapter.encryptEntity(entity);
            assertNotEquals(original, entity.getHandle());

            profileAdapter.decryptEntity(entity);
            assertEquals(original, entity.getHandle());
        }

        @Test
        @DisplayName("Consent context: no PII fields, entity unchanged after encrypt/decrypt")
        void consentContext_noPiiFields_entityUnchanged() {
            ConsentJpaEntity entity = consentEntity();
            String purposeBefore = entity.getPurpose();

            consentAdapter.encryptEntity(entity);
            consentAdapter.decryptEntity(entity);

            assertEquals(purposeBefore, entity.getPurpose(), "Purpose must be unchanged (not PII)");
        }

        @Test
        @DisplayName("Segment context: no PII fields, entity unchanged after encrypt/decrypt")
        void segmentContext_noPiiFields_entityUnchanged() {
            SegmentJpaEntity entity = segmentEntity();
            Set<String> tagsBefore = new HashSet<>(entity.getTags());

            segmentAdapter.encryptEntity(entity);
            segmentAdapter.decryptEntity(entity);

            assertEquals(tagsBefore, entity.getTags(), "Tags must be unchanged (not PII)");
        }

        @Test
        @DisplayName("Preference context: no PII fields, entity unchanged after encrypt/decrypt")
        void preferenceContext_noPiiFields_entityUnchanged() {
            PreferenceJpaEntity entity = preferenceEntity();
            Map<String, String> settingsBefore = new HashMap<>(entity.getSettings());

            preferenceAdapter.encryptEntity(entity);
            preferenceAdapter.decryptEntity(entity);

            assertEquals(settingsBefore, entity.getSettings(), "Settings must be unchanged (not PII)");
        }

        @Test
        @DisplayName("All four adapters can encrypt and decrypt Profile handle")
        void allFourAdapters_canEncryptAndDecryptProfileHandle() {
            String plaintext = "shared-user";
            DatabaseEncryptionAdapter[] adapters = {profileAdapter, consentAdapter, segmentAdapter, preferenceAdapter};

            for (DatabaseEncryptionAdapter adapter : adapters) {
                ProfileJpaEntity entity = profileEntity(plaintext);
                adapter.encryptEntity(entity);
                assertNotEquals(plaintext, entity.getHandle(), "Adapter must encrypt the handle");

                adapter.decryptEntity(entity);
                assertEquals(plaintext, entity.getHandle(), "Adapter must decrypt the handle back");
            }
        }
    }

    // -------------------------------------------------------------------------
    // All PII field types
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("All PII field types")
    class AllPiiFieldTypesTests {

        @Test
        @DisplayName("Email-like handle is encrypted and decryptable")
        void emailHandle_encryptedAndDecryptable() {
            String email = "user@example.com";
            ProfileJpaEntity entity = profileEntity(email);

            profileAdapter.encryptEntity(entity);
            assertNotEquals(email, entity.getHandle());

            profileAdapter.decryptEntity(entity);
            assertEquals(email, entity.getHandle());
        }

        @Test
        @DisplayName("Phone-like handle is encrypted and decryptable")
        void phoneHandle_encryptedAndDecryptable() {
            String phone = "+1-555-123-4567";
            ProfileJpaEntity entity = profileEntity(phone);

            profileAdapter.encryptEntity(entity);
            assertNotEquals(phone, entity.getHandle());

            profileAdapter.decryptEntity(entity);
            assertEquals(phone, entity.getHandle());
        }

        @Test
        @DisplayName("IP address-like handle is encrypted and decryptable")
        void ipAddressHandle_encryptedAndDecryptable() {
            String ip = "192.168.1.100";
            ProfileJpaEntity entity = profileEntity(ip);

            profileAdapter.encryptEntity(entity);
            assertNotEquals(ip, entity.getHandle());

            profileAdapter.decryptEntity(entity);
            assertEquals(ip, entity.getHandle());
        }

        @Test
        @DisplayName("Name-like handle is encrypted and decryptable")
        void nameHandle_encryptedAndDecryptable() {
            String name = "John Doe";
            ProfileJpaEntity entity = profileEntity(name);

            profileAdapter.encryptEntity(entity);
            assertNotEquals(name, entity.getHandle());

            profileAdapter.decryptEntity(entity);
            assertEquals(name, entity.getHandle());
        }

        @Test
        @DisplayName("Unicode handle is encrypted and decryptable")
        void unicodeHandle_encryptedAndDecryptable() {
            String unicode = "用户名@例子.中国";
            ProfileJpaEntity entity = profileEntity(unicode);

            profileAdapter.encryptEntity(entity);
            assertNotEquals(unicode, entity.getHandle());

            profileAdapter.decryptEntity(entity);
            assertEquals(unicode, entity.getHandle());
        }

        @Test
        @DisplayName("Empty string handle is encrypted and decryptable")
        void emptyStringHandle_encryptedAndDecryptable() {
            String empty = "";
            ProfileJpaEntity entity = profileEntity(empty);

            profileAdapter.encryptEntity(entity);
            // Empty string should be encrypted (not null)
            assertNotNull(entity.getHandle());

            profileAdapter.decryptEntity(entity);
            assertEquals(empty, entity.getHandle());
        }

        @Test
        @DisplayName("Long handle (>1KB) is encrypted and decryptable")
        void longHandle_encryptedAndDecryptable() {
            String longValue = "a".repeat(2000);
            ProfileJpaEntity entity = profileEntity(longValue);

            profileAdapter.encryptEntity(entity);
            assertNotEquals(longValue, entity.getHandle());

            profileAdapter.decryptEntity(entity);
            assertEquals(longValue, entity.getHandle());
        }
    }

    // -------------------------------------------------------------------------
    // Blind index generation
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Blind index generation during encryption")
    class BlindIndexTests {

        @Test
        @DisplayName("Blind index is generated for searchable handle field")
        void blindIndex_generatedForSearchableHandle() {
            ProfileJpaEntity entity = profileEntity("searchable@example.com");
            profileAdapter.encryptEntity(entity);

            assertNotNull(entity.getHandleBlindIndex(), "Blind index must be set");
            assertFalse(entity.getHandleBlindIndex().isBlank(), "Blind index must not be blank");
        }

        @Test
        @DisplayName("Blind index is null when handle is null")
        void blindIndex_nullWhenHandleIsNull() {
            ProfileJpaEntity entity = profileEntity(null);
            profileAdapter.encryptEntity(entity);

            assertNull(entity.getHandleBlindIndex(), "Blind index must be null when handle is null");
        }

        @Test
        @DisplayName("Blind index is preserved after decryption")
        void blindIndex_preservedAfterDecryption() {
            ProfileJpaEntity entity = profileEntity("preserved@example.com");
            profileAdapter.encryptEntity(entity);
            String blindIndex = entity.getHandleBlindIndex();

            profileAdapter.decryptEntity(entity);

            assertEquals(blindIndex, entity.getHandleBlindIndex(),
                    "Blind index must not be modified by decryption");
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static ProfileJpaEntity profileEntity(String handle) {
        ProfileJpaEntity entity = new ProfileJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setTenantId("integration-test-tenant");
        entity.setHandle(handle);
        return entity;
    }

    private static ConsentJpaEntity consentEntity() {
        ConsentJpaEntity entity = new ConsentJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setProfileId(UUID.randomUUID());
        entity.setTenantId("integration-test-tenant");
        entity.setPurpose("marketing");
        entity.setScope("email");
        entity.setStatus(ConsentStatus.GRANTED);
        return entity;
    }

    private static SegmentJpaEntity segmentEntity() {
        SegmentJpaEntity entity = new SegmentJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setProfileId(UUID.randomUUID());
        entity.setTenantId("integration-test-tenant");
        entity.setTags(new HashSet<>(Set.of("tag-a", "tag-b")));
        entity.setScores(new HashMap<>(Map.of("score-x", 0.5)));
        entity.setLastUpdated(Instant.now());
        return entity;
    }

    private static PreferenceJpaEntity preferenceEntity() {
        PreferenceJpaEntity entity = new PreferenceJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setProfileId(UUID.randomUUID());
        entity.setTenantId("integration-test-tenant");
        entity.setSettings(new HashMap<>(Map.of("theme", "dark", "language", "en")));
        entity.setLastUpdated(Instant.now());
        return entity;
    }

    // -------------------------------------------------------------------------
    // Test infrastructure stubs
    // -------------------------------------------------------------------------

    static final class StubKeyManager implements IKeyManager {
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
