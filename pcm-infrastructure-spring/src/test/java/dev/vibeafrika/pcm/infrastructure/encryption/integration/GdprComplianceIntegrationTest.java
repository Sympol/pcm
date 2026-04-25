package dev.vibeafrika.pcm.infrastructure.encryption.integration;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.*;
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
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * GDPR compliance integration tests.
 *
 * <p>Tests:
 * <ul>
 *   <li>Cryptographic erasure</li>
 *   <li>Deletion certificate generation</li>
 *   <li>Data portability export</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("GDPR Compliance Integration Tests")
class GdprComplianceIntegrationTest {

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

        blindIndexService = new BlindIndexService(keyManager, "gdpr-test-global-salt");
        encryptionService = new EncryptionService(keyManager, blindIndexService, auditLogger,
                new IVCounterImpl(new InMemoryIVCounterStorage()));
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private EncryptedDEK fakeEncryptedDEK(UUID kekId) {
        return EncryptedDEK.of(randomBytes(48), kekId);
    }

    private UUID setupUserDEK(UUID kekId, String userId) {
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(kekId));
        keyManager.initializeKEK(CONTEXT);
        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));
        Result<UUID, KeyError> result = keyManager.createUserDEK(userId, CONTEXT);
        assertTrue(result.isSuccess(), "User DEK creation must succeed");
        return result.getValue().orElseThrow();
    }

    // -------------------------------------------------------------------------
    // Cryptographic erasure
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Cryptographic erasure")
    class CryptographicErasureTests {

        @Test
        @DisplayName("User DEK is deleted from KMS on erasure request")
        void userDEK_deletedFromKMS_onErasureRequest() {
            UUID kekId = UUID.randomUUID();
            String userId = "gdpr-user-123";
            UUID userDEKId = setupUserDEK(kekId, userId);

            when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));

            Result<DeletionCertificate, KeyError> result = keyManager.deleteUserDEK(userId, CONTEXT);

            assertTrue(result.isSuccess(), "Cryptographic erasure must succeed");
            verify(kmsClient).deleteDEK(eq(userDEKId));
        }

        @Test
        @DisplayName("After erasure, user DEK is not accessible (data cannot be decrypted)")
        void afterErasure_userDEK_notAccessible() {
            UUID kekId = UUID.randomUUID();
            String userId = "gdpr-user-456";
            UUID userDEKId = setupUserDEK(kekId, userId);

            when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));
            keyManager.deleteUserDEK(userId, CONTEXT);

            // After deletion, getDEK should fail
            Result<DEKWithMetadata, KeyError> getDEKResult = keyManager.getDEK(userDEKId);
            assertTrue(getDEKResult.isFailure(),
                    "After cryptographic erasure, DEK must not be accessible");
            assertEquals("KEY_NOT_FOUND", getDEKResult.getError().get().getCode());
        }

        @Test
        @DisplayName("After erasure, DEK is evicted from cache")
        void afterErasure_DEK_evictedFromCache() {
            UUID kekId = UUID.randomUUID();
            String userId = "gdpr-user-789";
            UUID userDEKId = setupUserDEK(kekId, userId);

            // Populate cache
            DEK plainDEK = DEK.of(randomBytes(32));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                    .thenReturn(Result.success(plainDEK));
            keyManager.getDEK(userDEKId);
            assertTrue(dekCache.get(userDEKId).isPresent(), "DEK should be in cache before erasure");

            when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));
            keyManager.deleteUserDEK(userId, CONTEXT);

            assertFalse(dekCache.get(userDEKId).isPresent(),
                    "DEK must be evicted from cache after cryptographic erasure");
        }

        @Test
        @DisplayName("Erasure of one user does not affect other users' data")
        void erasureOfOneUser_doesNotAffectOtherUsers() {
            UUID kekId = UUID.randomUUID();
            when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(kekId));
            keyManager.initializeKEK(CONTEXT);
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

            UUID userADEKId = keyManager.createUserDEK("user-A", CONTEXT).getValue().orElseThrow();
            UUID userBDEKId = keyManager.createUserDEK("user-B", CONTEXT).getValue().orElseThrow();

            when(kmsClient.deleteDEK(eq(userADEKId))).thenReturn(Result.success(Unit.unit()));
            keyManager.deleteUserDEK("user-A", CONTEXT);

            // user-B's DEK should still be accessible
            DEK plainDEK = DEK.of(randomBytes(32));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                    .thenReturn(Result.success(plainDEK));

            Result<DEKWithMetadata, KeyError> userBResult = keyManager.getDEK(userBDEKId);
            assertTrue(userBResult.isSuccess(),
                    "user-B's DEK must remain accessible after user-A's erasure");
        }
    }

    // -------------------------------------------------------------------------
    // Deletion certificate generation
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Deletion certificate generation")
    class DeletionCertificateTests {

        @Test
        @DisplayName("Deletion certificate is returned after erasure")
        void deletionCertificate_returnedAfterErasure() {
            UUID kekId = UUID.randomUUID();
            String userId = "cert-user-123";
            UUID userDEKId = setupUserDEK(kekId, userId);

            when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));

            Result<DeletionCertificate, KeyError> result = keyManager.deleteUserDEK(userId, CONTEXT);

            assertTrue(result.isSuccess(), "Deletion must return a certificate");
            DeletionCertificate cert = result.getValue().get();

            assertNotNull(cert, "Deletion certificate must not be null");
            assertEquals(userDEKId, cert.getKeyId(), "Certificate must contain the deleted key ID");
            assertEquals(userId, cert.getUserId(), "Certificate must contain the user ID");
            assertEquals(CONTEXT, cert.getContext(), "Certificate must contain the bounded context");
            assertNotNull(cert.getDeletedAt(), "Certificate must contain a deletion timestamp");
        }

        @Test
        @DisplayName("Deletion certificate has a valid HMAC signature")
        void deletionCertificate_hasValidHmacSignature() {
            UUID kekId = UUID.randomUUID();
            String userId = "cert-user-456";
            UUID userDEKId = setupUserDEK(kekId, userId);
            keyManager.initializeBlindIndexKey();

            when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));

            Result<DeletionCertificate, KeyError> result = keyManager.deleteUserDEK(userId, CONTEXT);

            assertTrue(result.isSuccess());
            DeletionCertificate cert = result.getValue().get();

            assertNotNull(cert.getSignature(), "Certificate must have a signature");
            assertFalse(cert.getSignature().isBlank(), "Certificate signature must not be blank");
            // HMAC-SHA256 produces 64 hex characters
            assertEquals(64, cert.getSignature().length(),
                    "HMAC-SHA256 signature must be 64 hex characters");
        }

        @Test
        @DisplayName("Deletion certificate timestamp is recent")
        void deletionCertificate_timestampIsRecent() {
            UUID kekId = UUID.randomUUID();
            String userId = "cert-user-789";
            UUID userDEKId = setupUserDEK(kekId, userId);

            Instant before = Instant.now();
            when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));
            Result<DeletionCertificate, KeyError> result = keyManager.deleteUserDEK(userId, CONTEXT);
            Instant after = Instant.now();

            assertTrue(result.isSuccess());
            Instant deletedAt = result.getValue().get().getDeletedAt();

            assertFalse(deletedAt.isBefore(before), "Deletion timestamp must not be before the request");
            assertFalse(deletedAt.isAfter(after), "Deletion timestamp must not be after the response");
        }

        @Test
        @DisplayName("Deletion event is logged with GDPR Article 17 reference")
        void deletionEvent_loggedWithGdprArticle17Reference() {
            UUID kekId = UUID.randomUUID();
            String userId = "gdpr-audit-user";
            UUID userDEKId = setupUserDEK(kekId, userId);

            when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));
            keyManager.deleteUserDEK(userId, CONTEXT);

            ArgumentCaptor<SecurityEvent> eventCaptor = ArgumentCaptor.forClass(SecurityEvent.class);
            verify(auditLogger, atLeastOnce()).logSecurityEvent(eventCaptor.capture());

            SecurityEvent deletionEvent = eventCaptor.getAllValues().stream()
                    .filter(e -> "USER_DEK_DELETED".equals(e.getEventType()))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("No USER_DEK_DELETED event logged"));

            assertTrue(deletionEvent.getMetadata().containsKey("gdprArticle"),
                    "Deletion event must reference GDPR article");
            assertEquals("17", deletionEvent.getMetadata().get("gdprArticle"),
                    "Deletion event must reference GDPR Article 17");
        }
    }

    // -------------------------------------------------------------------------
    // Data portability export 
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Data portability export")
    class DataPortabilityTests {

        @Test
        @DisplayName("Encrypted data can be decrypted for portability export")
        void encryptedData_canBeDecrypted_forPortabilityExport() {
            UUID kekId = UUID.randomUUID();
            when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(kekId));
            keyManager.initializeKEK(CONTEXT);
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(kekId)));
            keyManager.rotateDEK(CONTEXT);

            // Encrypt user data
            DEK plainDEK = DEK.of(randomBytes(32));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                    .thenReturn(Result.success(plainDEK));

            List<String> userData = List.of(
                    "alice@example.com",
                    "+1-555-123-4567",
                    "Alice Smith"
            );

            Result<List<Ciphertext>, EncryptionError> encResult =
                    encryptionService.encryptBatch(userData, CONTEXT);
            assertTrue(encResult.isSuccess(), "Batch encryption must succeed");

            // Decrypt for portability export
            Result<List<String>, DecryptionError> decResult =
                    encryptionService.decryptBatch(encResult.getValue().get(), CONTEXT);
            assertTrue(decResult.isSuccess(),
                    "Batch decryption for portability export must succeed");

            assertEquals(userData, decResult.getValue().get(),
                    "Decrypted data must match original for portability export");
        }

        @Test
        @DisplayName("Portability export preserves all PII field types")
        void portabilityExport_preservesAllPiiFieldTypes() {
            UUID kekId = UUID.randomUUID();
            when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(kekId));
            keyManager.initializeKEK(CONTEXT);
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(fakeEncryptedDEK(kekId)));
            keyManager.rotateDEK(CONTEXT);

            DEK plainDEK = DEK.of(randomBytes(32));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                    .thenReturn(Result.success(plainDEK));

            // Test various PII field types
            String email = "user@example.com";
            String phone = "+1-555-987-6543";
            String name = "John Doe";
            String ip = "192.168.1.1";

            for (String piiValue : List.of(email, phone, name, ip)) {
                Result<Ciphertext, EncryptionError> encResult =
                        encryptionService.encrypt(piiValue, CONTEXT);
                assertTrue(encResult.isSuccess(), "Encryption of PII must succeed: " + piiValue);

                Result<String, DecryptionError> decResult =
                        encryptionService.decrypt(encResult.getValue().get(), CONTEXT);
                assertTrue(decResult.isSuccess(), "Decryption for portability must succeed: " + piiValue);
                assertEquals(piiValue, decResult.getValue().get(),
                        "Portability export must preserve PII value: " + piiValue);
            }
        }

        @Test
        @DisplayName("Portability export fails gracefully after cryptographic erasure")
        void portabilityExport_failsGracefully_afterCryptographicErasure() {
            UUID kekId = UUID.randomUUID();
            String userId = "portability-user";
            UUID userDEKId = setupUserDEK(kekId, userId);

            // Encrypt data with user DEK
            DEK plainDEK = DEK.of(randomBytes(32));
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                    .thenReturn(Result.success(plainDEK));

            // Simulate encryption with user DEK (by getting the DEK and encrypting)
            Result<DEKWithMetadata, KeyError> dekResult = keyManager.getDEK(userDEKId);
            assertTrue(dekResult.isSuccess());

            // Perform cryptographic erasure
            when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));
            Result<DeletionCertificate, KeyError> erasureResult = keyManager.deleteUserDEK(userId, CONTEXT);
            assertTrue(erasureResult.isSuccess(), "Erasure must succeed");

            // After erasure, the DEK is gone - portability export should fail
            Result<DEKWithMetadata, KeyError> postErasureResult = keyManager.getDEK(userDEKId);
            assertTrue(postErasureResult.isFailure(),
                    "After cryptographic erasure, data portability export must fail (data is erased)");
        }
    }
}
