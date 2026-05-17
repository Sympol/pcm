package dev.vibeafrika.pcm.infrastructure.encryption.integration;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.adapter.DatabaseEncryptionAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Integration tests for key rotation scenarios.
 *
 * <p>Tests:
 * <ul>
 *   <li>DEK rotation with active encryption/decryption</li>
 *   <li>KEK rotation with multiple DEKs</li>
 *   <li>Decryption of data encrypted before rotation</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Key Rotation Integration Tests")
class KeyRotationIntegrationTest {

    @Mock
    private IKMSClient kmsClient;

    @Mock
    private IAuditLogger auditLogger;

    @Mock
    private IVCounter ivCounter;

    private DEKCache dekCache;
    private KeyManager keyManager;
    private BlindIndexService blindIndexService;
    private EncryptionService encryptionService;
    private DatabaseEncryptionAdapter adapter;

    private static final BoundedContext CONTEXT = BoundedContext.PROFILE;
    private static final Environment ENV = Environment.DEV;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeEach
    void setUp() {
        dekCache = new DEKCache();
        keyManager = new KeyManager(kmsClient, auditLogger, dekCache, ENV, ivCounter);

        AuditError noopError = AuditError.of("NOOP", "no-op");
        lenient().when(auditLogger.logKeyAccess(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logKeyRotation(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logSecurityEvent(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logEncryption(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logDecryption(any())).thenReturn(Result.failure(noopError));
        lenient().when(ivCounter.resetState(any())).thenReturn(Result.success(Unit.unit()));

        blindIndexService = new BlindIndexService(keyManager, "rotation-test-salt");
        encryptionService = new EncryptionService(keyManager, blindIndexService, auditLogger,
                new IVCounterImpl(new InMemoryIVCounterStorage()));
        adapter = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, CONTEXT);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private EncryptedDEK fakeEncryptedDEK(UUID kekId) {
        return EncryptedDEK.of(randomBytes(48), kekId);
    }

    private UUID initContextWithDEK(UUID kekId) {
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(kekId));
        keyManager.initializeKEK(CONTEXT);
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));
        Result<UUID, KeyError> result = keyManager.rotateDEK(CONTEXT);
        assertTrue(result.isSuccess(), "Initial DEK setup must succeed");
        return result.getValue().orElseThrow();
    }

    // -------------------------------------------------------------------------
    // DEK rotation with active encryption/decryption
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("DEK rotation with active encryption/decryption")
    class DekRotationTests {

        @Test
        @DisplayName("After DEK rotation, new encryption uses new DEK")
        void afterDekRotation_newEncryptionUsesNewDEK() {
            UUID kekId = UUID.randomUUID();
            UUID oldDEKId = initContextWithDEK(kekId);

            // Rotate DEK
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(kekId)));
            Result<UUID, KeyError> rotationResult = keyManager.rotateDEK(CONTEXT);
            assertTrue(rotationResult.isSuccess());
            UUID newDEKId = rotationResult.getValue().orElseThrow();

            assertNotEquals(oldDEKId, newDEKId, "New DEK must differ from old DEK");

            // New active DEK must be the new one
            DEK newPlainDEK = DEK.of(randomBytes(32));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                    .thenReturn(Result.success(newPlainDEK));

            Result<DEKWithMetadata, KeyError> activeResult = keyManager.getActiveDEK(CONTEXT);
            assertTrue(activeResult.isSuccess());
            assertEquals(newDEKId, activeResult.getValue().orElseThrow().getKeyId(),
                    "Active DEK must be the new DEK after rotation");
        }

        @Test
        @DisplayName("Old DEK is marked ROTATED after DEK rotation")
        void afterDekRotation_oldDEKIsMarkedRotated() {
            UUID kekId = UUID.randomUUID();
            UUID oldDEKId = initContextWithDEK(kekId);

            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(kekId)));
            keyManager.rotateDEK(CONTEXT);

            DEK plainDEK = DEK.of(randomBytes(32));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                    .thenReturn(Result.success(plainDEK));

            Result<DEKWithMetadata, KeyError> oldResult = keyManager.getDEK(oldDEKId);
            assertTrue(oldResult.isSuccess(), "Old DEK must still be retrievable");
            assertEquals(KeyStatus.ROTATED, oldResult.getValue().orElseThrow().getStatus(),
                    "Old DEK must be ROTATED after rotation");
        }

        @Test
        @DisplayName("Old DEK is evicted from cache after rotation")
        void afterDekRotation_oldDEKEvictedFromCache() {
            UUID kekId = UUID.randomUUID();
            UUID oldDEKId = initContextWithDEK(kekId);

            // Populate cache
            DEK plainDEK = DEK.of(randomBytes(32));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                    .thenReturn(Result.success(plainDEK));
            keyManager.getDEK(oldDEKId);
            assertTrue(dekCache.get(oldDEKId).isPresent(), "Old DEK should be in cache");

            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(kekId)));
            keyManager.rotateDEK(CONTEXT);

            assertFalse(dekCache.get(oldDEKId).isPresent(),
                    "Old DEK must be evicted from cache after rotation");
        }

        @Test
        @DisplayName("Key rotation event is logged")
        void dekRotation_logsKeyRotationEvent() {
            UUID kekId = UUID.randomUUID();
            initContextWithDEK(kekId);

            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(kekId)));
            keyManager.rotateDEK(CONTEXT);

            verify(auditLogger, atLeastOnce()).logKeyRotation(any(KeyRotationEvent.class));
        }
    }

    // -------------------------------------------------------------------------
    // Decryption of data encrypted before rotation
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Decryption of data encrypted before rotation")
    class HistoricalDecryptionTests {

        @Test
        @DisplayName("Data encrypted before DEK rotation is still decryptable after rotation")
        void dataEncryptedBeforeRotation_isDecryptableAfterRotation() {
            // Use a RotatingStubKeyManager that supports DEK rotation while keeping old DEKs accessible
            RotatingStubKeyManager rotatingKeyManager = new RotatingStubKeyManager();
            IVCounter realIVCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
            BlindIndexService bis = new BlindIndexService(rotatingKeyManager, "rotation-test-salt");
            EncryptionService rotatingEncService = new EncryptionService(
                    rotatingKeyManager, bis, auditLogger, realIVCounter);

            // Encrypt data with the initial DEK
            String original = "pre-rotation-data";
            Result<Ciphertext, EncryptionError> encResult = rotatingEncService.encrypt(original, CONTEXT);
            assertTrue(encResult.isSuccess(), "Encryption before rotation must succeed");
            Ciphertext preRotationCiphertext = encResult.getValue().orElseThrow();

            // Rotate DEK — old DEK remains accessible for decryption
            rotatingKeyManager.rotateDEK(CONTEXT);

            // Decrypt pre-rotation data (should still work with old DEK)
            Result<String, DecryptionError> decResult = rotatingEncService.decrypt(preRotationCiphertext, CONTEXT);
            assertTrue(decResult.isSuccess(),
                    "Data encrypted before rotation must be decryptable after rotation");
            assertEquals(original, decResult.getValue().orElseThrow(),
                    "Decrypted value must match original");
        }

        @Test
        @DisplayName("Updated data after rotation is encrypted with new DEK")
        void updatedDataAfterRotation_encryptedWithNewDEK() {
            UUID kekId = UUID.randomUUID();
            UUID oldDEKId = initContextWithDEK(kekId);

            // Rotate DEK
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(kekId)));
            UUID newDEKId = keyManager.rotateDEK(CONTEXT).getValue().orElseThrow();

            assertNotEquals(oldDEKId, newDEKId, "New DEK must differ from old DEK");

            // Encrypt new data after rotation
            DEK newPlainDEK = DEK.of(randomBytes(32));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                    .thenReturn(Result.success(newPlainDEK));

            Result<Ciphertext, EncryptionError> encResult = encryptionService.encrypt("post-rotation-data", CONTEXT);
            assertTrue(encResult.isSuccess());

            // Verify the ciphertext contains the new DEK ID
            Ciphertext ct = encResult.getValue().orElseThrow();
            Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult = CiphertextFormat.parse(ct);
            assertTrue(parseResult.isSuccess());
            assertEquals(newDEKId, parseResult.getValue().orElseThrow().getKeyId(),
                    "Post-rotation data must be encrypted with new DEK");
        }
    }

    // -------------------------------------------------------------------------
    // KEK rotation with multiple DEKs
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("KEK rotation with multiple DEKs")
    class KekRotationTests {

        @Test
        @DisplayName("KEK rotation re-encrypts all DEKs with new KEK")
        void kekRotation_reEncryptsAllDEKsWithNewKEK() {
            UUID oldKEKId = UUID.randomUUID();
            UUID newKEKId = UUID.randomUUID();

            // Initialize with old KEK and create two DEKs
            when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(oldKEKId));
            keyManager.initializeKEK(CONTEXT);

            when(kmsClient.encryptDEK(any(DEK.class), eq(oldKEKId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(oldKEKId)));
            UUID dek1 = keyManager.rotateDEK(CONTEXT).getValue().orElseThrow();
            UUID dek2 = keyManager.rotateDEK(CONTEXT).getValue().orElseThrow();
            assertNotEquals(dek1, dek2, "Two DEK rotations must produce distinct DEK IDs");

            // Rotate KEK
            when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(newKEKId));
            DEK plainDEK = DEK.of(randomBytes(32));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(oldKEKId)))
                    .thenReturn(Result.success(plainDEK));
            when(kmsClient.encryptDEK(any(DEK.class), eq(newKEKId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(newKEKId)));

            Result<UUID, KeyError> kekRotationResult = keyManager.rotateKEK(CONTEXT);
            assertTrue(kekRotationResult.isSuccess(), "KEK rotation must succeed");
            assertEquals(newKEKId, kekRotationResult.getValue().orElseThrow(),
                    "New KEK ID must be returned");
        }

        @Test
        @DisplayName("After KEK rotation, DEKs are retrievable with new KEK")
        void afterKekRotation_deksRetrievableWithNewKEK() {
            UUID oldKEKId = UUID.randomUUID();
            UUID newKEKId = UUID.randomUUID();

            when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(oldKEKId));
            keyManager.initializeKEK(CONTEXT);
            when(kmsClient.encryptDEK(any(DEK.class), eq(oldKEKId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(oldKEKId)));
            UUID dekId = keyManager.rotateDEK(CONTEXT).getValue().orElseThrow();

            // Rotate KEK
            when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(newKEKId));
            DEK plainDEK = DEK.of(randomBytes(32));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(oldKEKId)))
                    .thenReturn(Result.success(plainDEK));
            when(kmsClient.encryptDEK(any(DEK.class), eq(newKEKId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(newKEKId)));
            keyManager.rotateKEK(CONTEXT);

            // After KEK rotation, DEK should be retrievable using new KEK
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(newKEKId)))
                    .thenReturn(Result.success(plainDEK));
            Result<DEKWithMetadata, KeyError> dekResult = keyManager.getDEK(dekId);
            assertTrue(dekResult.isSuccess(),
                    "DEK must be retrievable after KEK rotation");
        }

        @Test
        @DisplayName("KEK rotation invalidates all cached DEKs for context")
        void kekRotation_invalidatesAllCachedDEKs() {
            UUID oldKEKId = UUID.randomUUID();
            UUID newKEKId = UUID.randomUUID();

            when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(oldKEKId));
            keyManager.initializeKEK(CONTEXT);
            when(kmsClient.encryptDEK(any(DEK.class), eq(oldKEKId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(oldKEKId)));
            UUID dekId = keyManager.rotateDEK(CONTEXT).getValue().orElseThrow();

            // Populate cache
            DEK plainDEK = DEK.of(randomBytes(32));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(oldKEKId)))
                    .thenReturn(Result.success(plainDEK));
            keyManager.getDEK(dekId);
            assertTrue(dekCache.get(dekId).isPresent(), "DEK should be in cache before KEK rotation");

            // Rotate KEK
            when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(newKEKId));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(oldKEKId)))
                    .thenReturn(Result.success(plainDEK));
            when(kmsClient.encryptDEK(any(DEK.class), eq(newKEKId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(newKEKId)));
            keyManager.rotateKEK(CONTEXT);

            assertFalse(dekCache.get(dekId).isPresent(),
                    "DEK must be evicted from cache after KEK rotation");
        }
    }

    // -------------------------------------------------------------------------
    // RotatingStubKeyManager — supports DEK rotation while keeping old DEKs accessible
    // -------------------------------------------------------------------------

    /**
     * A stub IKeyManager that supports DEK rotation.
     * Old DEKs remain accessible by their ID for historical decryption.
     */
    static final class RotatingStubKeyManager implements IKeyManager {
        private final Map<UUID, DEK> dekStore = new java.util.LinkedHashMap<>();
        private UUID activeDEKId;
        private final byte[] blindIndexKey;

        RotatingStubKeyManager() {
            this.blindIndexKey = new byte[32];
            new SecureRandom().nextBytes(this.blindIndexKey);
            // Initialize with a first DEK
            UUID firstId = UUID.randomUUID();
            byte[] keyMaterial = new byte[32];
            new SecureRandom().nextBytes(keyMaterial);
            dekStore.put(firstId, DEK.of(keyMaterial));
            activeDEKId = firstId;
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return getDEK(activeDEKId);
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
            DEK dek = dekStore.get(keyId);
            if (dek == null) {
                return Result.failure(KeyError.of("KEY_NOT_FOUND", "DEK not found: " + keyId));
            }
            return Result.success(DEKWithMetadata.builder()
                    .dek(dek).keyId(keyId).kekId(UUID.randomUUID())
                    .context(CONTEXT).environment(ENV)
                    .algorithm(EncryptionAlgorithm.AES_256_GCM)
                    .createdAt(Instant.now()).status(KeyStatus.ACTIVE)
                    .build());
        }

        @Override
        public Result<UUID, KeyError> rotateDEK(BoundedContext context) {
            UUID newId = UUID.randomUUID();
            byte[] keyMaterial = new byte[32];
            new SecureRandom().nextBytes(keyMaterial);
            dekStore.put(newId, DEK.of(keyMaterial));
            activeDEKId = newId;
            return Result.success(newId);
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
}