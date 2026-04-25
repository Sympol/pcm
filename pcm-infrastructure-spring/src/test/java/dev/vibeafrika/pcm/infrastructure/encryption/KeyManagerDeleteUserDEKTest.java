package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.SecureRandom;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link KeyManager#deleteUserDEK(String, BoundedContext)}.
 *
 * <p>Validates Requirements:
 * <ul>
 *   <li>WHEN a user requests data deletion under GDPR Article 17, THE Key_Manager SHALL
 *       delete the user-specific DEK within 30 days</li>
 *   <li>WHEN a user-specific DEK is deleted, THE system SHALL generate a cryptographic
 *       erasure certificate as proof of deletion</li>
 *   <li>THE Audit_Logger SHALL maintain an audit trail of all deletion requests and
 *       completions</li>
 *   <li>THE Audit_Logger SHALL verify that deleted data cannot be decrypted after DEK
 *       deletion</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class KeyManagerDeleteUserDEKTest {

    @Mock
    private IKMSClient kmsClient;

    @Mock
    private IAuditLogger auditLogger;

    @Mock
    private IVCounter ivCounter;

    private DEKCache dekCache;
    private KeyManager keyManager;

    private static final BoundedContext CONTEXT = BoundedContext.PROFILE;
    private static final Environment ENV = Environment.PROD;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeEach
    void setUp() {
        dekCache = new DEKCache();
        keyManager = new KeyManager(kmsClient, auditLogger, dekCache, ENV, ivCounter);

        // Stub audit logger — KeyManager ignores the return value
        AuditError noopError = AuditError.of("NOOP", "no-op");
        lenient().when(auditLogger.logKeyAccess(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logKeyRotation(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logSecurityEvent(any())).thenReturn(Result.failure(noopError));
        lenient().when(ivCounter.resetState(any())).thenReturn(Result.success(Unit.unit()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private EncryptedDEK fakeEncryptedDEK(UUID kekId) {
        return EncryptedDEK.of(randomBytes(48), kekId);
    }

    /**
     * Sets up a KEK for the context and creates a user-specific DEK.
     * Returns the user DEK UUID.
     */
    private UUID setupUserDEK(UUID kekId, String userId) {
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(kekId));
        keyManager.initializeKEK(CONTEXT);

        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        Result<UUID, KeyError> result = keyManager.createUserDEK(userId, CONTEXT);
        assertTrue(result.isSuccess(), "User DEK creation should succeed");
        return result.getValue().orElseThrow();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: Identify and delete user DEK from KMS 
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that deleteUserDEK finds the user-specific DEK and deletes it from KMS.
     */
    @Test
    void deleteUserDEK_deletesFromKMS() {
        UUID kekId = UUID.randomUUID();
        String userId = "user-123";
        UUID userDEKId = setupUserDEK(kekId, userId);

        when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));

        Result<DeletionCertificate, KeyError> result = keyManager.deleteUserDEK(userId, CONTEXT);

        assertTrue(result.isSuccess(), "deleteUserDEK should succeed");
        verify(kmsClient).deleteDEK(eq(userDEKId));
    }

    /**
     * Verifies that deleteUserDEK returns an error when no user DEK exists.
     */
    @Test
    void deleteUserDEK_noUserDEKExists_returnsError() {
        UUID kekId = UUID.randomUUID();
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(kekId));
        keyManager.initializeKEK(CONTEXT);

        Result<DeletionCertificate, KeyError> result = keyManager.deleteUserDEK("nonexistent-user", CONTEXT);

        assertTrue(result.isFailure(), "deleteUserDEK should fail when no user DEK exists");
        assertEquals("USER_DEK_NOT_FOUND", result.getError().orElseThrow().getCode());
    }

    /**
     * Verifies that deleteUserDEK returns an error when KMS deletion fails.
     */
    @Test
    void deleteUserDEK_kmsDeleteFails_returnsError() {
        UUID kekId = UUID.randomUUID();
        String userId = "user-456";
        UUID userDEKId = setupUserDEK(kekId, userId);

        when(kmsClient.deleteDEK(eq(userDEKId)))
                .thenReturn(Result.failure(KMSError.of("KMS_DELETE_FAILED", "KMS unavailable")));

        Result<DeletionCertificate, KeyError> result = keyManager.deleteUserDEK(userId, CONTEXT);

        assertTrue(result.isFailure(), "deleteUserDEK should fail when KMS deletion fails");
        assertEquals("KMS_DELETE_FAILED", result.getError().orElseThrow().getCode());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: Cache invalidation after deletion 
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that the user DEK is evicted from cache after deletion.
     */
    @Test
    void deleteUserDEK_invalidatesDEKFromCache() {
        UUID kekId = UUID.randomUUID();
        String userId = "user-789";
        UUID userDEKId = setupUserDEK(kekId, userId);

        // Populate cache by calling getDEK
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                .thenReturn(Result.success(plainDEK));
        keyManager.getDEK(userDEKId);
        assertTrue(dekCache.get(userDEKId).isPresent(), "DEK should be in cache before deletion");

        when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));

        keyManager.deleteUserDEK(userId, CONTEXT);

        assertFalse(dekCache.get(userDEKId).isPresent(),
                "DEK must be evicted from cache after deletion");
    }

    /**
     * Verifies that after deletion, getDEK returns an error (data cannot be decrypted).
     */
    @Test
    void deleteUserDEK_afterDeletion_getDEKFails() {
        UUID kekId = UUID.randomUUID();
        String userId = "user-abc";
        UUID userDEKId = setupUserDEK(kekId, userId);

        when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));

        keyManager.deleteUserDEK(userId, CONTEXT);

        // After deletion, getDEK should fail because metadata is removed
        Result<DEKWithMetadata, KeyError> getDEKResult = keyManager.getDEK(userDEKId);
        assertTrue(getDEKResult.isFailure(),
                "getDEK must fail after user DEK deletion (data cannot be decrypted)");
        assertEquals("KEY_NOT_FOUND", getDEKResult.getError().orElseThrow().getCode());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: Deletion certificate generation 
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that a deletion certificate is returned with correct fields.
     */
    @Test
    void deleteUserDEK_returnsDeletionCertificate() {
        UUID kekId = UUID.randomUUID();
        String userId = "user-cert-test";
        UUID userDEKId = setupUserDEK(kekId, userId);

        when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));

        Result<DeletionCertificate, KeyError> result = keyManager.deleteUserDEK(userId, CONTEXT);

        assertTrue(result.isSuccess(), "deleteUserDEK should return a deletion certificate");
        DeletionCertificate cert = result.getValue().orElseThrow();

        assertEquals(userDEKId, cert.getKeyId(), "Certificate must contain the deleted key ID");
        assertEquals(userId, cert.getUserId(), "Certificate must contain the user ID");
        assertEquals(CONTEXT, cert.getContext(), "Certificate must contain the bounded context");
        assertNotNull(cert.getDeletedAt(), "Certificate must contain a deletion timestamp");
        assertNotNull(cert.getSignature(), "Certificate must contain a signature");
        assertFalse(cert.getSignature().isBlank(), "Certificate signature must not be blank");
    }

    /**
     * Verifies that the deletion certificate signature is an HMAC-SHA256 hex string.
     */
    @Test
    void deleteUserDEK_certificateSignatureIsHmacHex() {
        UUID kekId = UUID.randomUUID();
        String userId = "user-sig-test";
        UUID userDEKId = setupUserDEK(kekId, userId);

        // Initialize blind index key so HMAC-SHA256 is used
        keyManager.initializeBlindIndexKey();

        when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));

        Result<DeletionCertificate, KeyError> result = keyManager.deleteUserDEK(userId, CONTEXT);

        assertTrue(result.isSuccess());
        String signature = result.getValue().orElseThrow().getSignature();

        // HMAC-SHA256 produces 32 bytes = 64 hex characters
        assertEquals(64, signature.length(),
                "HMAC-SHA256 signature must be 64 hex characters");
        assertTrue(signature.matches("[0-9a-f]+"),
                "Signature must be a lowercase hex string");
    }

    /**
     * Verifies that two deletion certificates for different users have different signatures.
     */
    @Test
    void deleteUserDEK_differentUsers_differentSignatures() {
        UUID kekId = UUID.randomUUID();
        keyManager.initializeBlindIndexKey();

        // Create DEKs for two different users
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(kekId));
        keyManager.initializeKEK(CONTEXT);

        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        UUID dek1 = keyManager.createUserDEK("user-A", CONTEXT).getValue().orElseThrow();
        UUID dek2 = keyManager.createUserDEK("user-B", CONTEXT).getValue().orElseThrow();

        when(kmsClient.deleteDEK(any())).thenReturn(Result.success(Unit.unit()));

        DeletionCertificate cert1 = keyManager.deleteUserDEK("user-A", CONTEXT).getValue().orElseThrow();
        DeletionCertificate cert2 = keyManager.deleteUserDEK("user-B", CONTEXT).getValue().orElseThrow();

        assertNotEquals(cert1.getSignature(), cert2.getSignature(),
                "Different users must produce different deletion certificate signatures");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4: Audit logging of deletion event
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that a security event is logged when a user DEK is deleted.
     */
    @Test
    void deleteUserDEK_logsSecurityEvent() {
        UUID kekId = UUID.randomUUID();
        String userId = "user-audit-test";
        UUID userDEKId = setupUserDEK(kekId, userId);

        when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));

        keyManager.deleteUserDEK(userId, CONTEXT);

        ArgumentCaptor<SecurityEvent> eventCaptor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(auditLogger, atLeastOnce()).logSecurityEvent(eventCaptor.capture());

        SecurityEvent deletionEvent = eventCaptor.getAllValues().stream()
                .filter(e -> "USER_DEK_DELETED".equals(e.getEventType()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No USER_DEK_DELETED security event logged"));

        assertEquals(userDEKId, deletionEvent.getKeyId(),
                "Deletion event must reference the deleted key ID");
        assertEquals(CONTEXT, deletionEvent.getContext(),
                "Deletion event must reference the bounded context");
        assertEquals("CRITICAL", deletionEvent.getSeverity(),
                "Deletion event must be logged at CRITICAL severity");
        assertNotNull(deletionEvent.getTimestamp(), "Deletion event must have a timestamp");
    }

    /**
     * Verifies that the deletion event description references GDPR Article 17.
     */
    @Test
    void deleteUserDEK_logsGdprArticle17Reference() {
        UUID kekId = UUID.randomUUID();
        String userId = "user-gdpr-test";
        UUID userDEKId = setupUserDEK(kekId, userId);

        when(kmsClient.deleteDEK(eq(userDEKId))).thenReturn(Result.success(Unit.unit()));

        keyManager.deleteUserDEK(userId, CONTEXT);

        ArgumentCaptor<SecurityEvent> eventCaptor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(auditLogger, atLeastOnce()).logSecurityEvent(eventCaptor.capture());

        SecurityEvent deletionEvent = eventCaptor.getAllValues().stream()
                .filter(e -> "USER_DEK_DELETED".equals(e.getEventType()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No USER_DEK_DELETED security event logged"));

        // Verify GDPR Article 17 is referenced in the event metadata
        assertTrue(deletionEvent.getMetadata().containsKey("gdprArticle"),
                "Deletion event metadata must reference GDPR article");
        assertEquals("17", deletionEvent.getMetadata().get("gdprArticle"),
                "Deletion event must reference GDPR Article 17");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 5: Isolation — only the target user's DEK is deleted
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Verifies that deleting one user's DEK does not affect another user's DEK.
     */
    @Test
    void deleteUserDEK_onlyDeletesTargetUserDEK() {
        UUID kekId = UUID.randomUUID();
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(kekId));
        keyManager.initializeKEK(CONTEXT);

        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));

        UUID userADEKId = keyManager.createUserDEK("user-A", CONTEXT).getValue().orElseThrow();
        UUID userBDEKId = keyManager.createUserDEK("user-B", CONTEXT).getValue().orElseThrow();

        when(kmsClient.deleteDEK(eq(userADEKId))).thenReturn(Result.success(Unit.unit()));

        // Delete only user-A's DEK
        Result<DeletionCertificate, KeyError> result = keyManager.deleteUserDEK("user-A", CONTEXT);
        assertTrue(result.isSuccess(), "Deletion of user-A DEK should succeed");

        // user-B's DEK should still be retrievable
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                .thenReturn(Result.success(plainDEK));

        Result<DEKWithMetadata, KeyError> userBResult = keyManager.getDEK(userBDEKId);
        assertTrue(userBResult.isSuccess(),
                "user-B's DEK must remain accessible after user-A's DEK is deleted");

        // user-A's DEK should be gone
        Result<DEKWithMetadata, KeyError> userAResult = keyManager.getDEK(userADEKId);
        assertTrue(userAResult.isFailure(),
                "user-A's DEK must not be accessible after deletion");
    }

    /**
     * Verifies that deleting a user DEK in one context does not affect the same user's
     * DEK in another context.
     */
    @Test
    void deleteUserDEK_onlyDeletesInTargetContext() {
        UUID profileKEKId = UUID.randomUUID();
        UUID consentKEKId = UUID.randomUUID();
        String userId = "user-cross-context";

        // Set up PROFILE context
        when(kmsClient.generateKEK(CONTEXT, ENV)).thenReturn(Result.success(profileKEKId));
        keyManager.initializeKEK(CONTEXT);
        when(kmsClient.encryptDEK(any(DEK.class), eq(profileKEKId)))
                .thenReturn(Result.success(fakeEncryptedDEK(profileKEKId)));
        UUID profileDEKId = keyManager.createUserDEK(userId, CONTEXT).getValue().orElseThrow();

        // Set up CONSENT context
        BoundedContext consentCtx = BoundedContext.CONSENT;
        when(kmsClient.generateKEK(consentCtx, ENV)).thenReturn(Result.success(consentKEKId));
        keyManager.initializeKEK(consentCtx);
        when(kmsClient.encryptDEK(any(DEK.class), eq(consentKEKId)))
                .thenReturn(Result.success(fakeEncryptedDEK(consentKEKId)));
        UUID consentDEKId = keyManager.createUserDEK(userId, consentCtx).getValue().orElseThrow();

        // Delete only the PROFILE DEK
        when(kmsClient.deleteDEK(eq(profileDEKId))).thenReturn(Result.success(Unit.unit()));
        Result<DeletionCertificate, KeyError> result = keyManager.deleteUserDEK(userId, CONTEXT);
        assertTrue(result.isSuccess(), "Deletion in PROFILE context should succeed");

        // CONSENT DEK should still be accessible
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(consentKEKId)))
                .thenReturn(Result.success(plainDEK));

        Result<DEKWithMetadata, KeyError> consentResult = keyManager.getDEK(consentDEKId);
        assertTrue(consentResult.isSuccess(),
                "CONSENT DEK must remain accessible after PROFILE DEK deletion");
    }
}
