package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.domain.encryption.AuditError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link SecretManager}.
 *
 * Tests verify:
 * - Secret storage in KMS
 * - Secret rotation schedules
 * - Secret access logging
 */
@ExtendWith(MockitoExtension.class)
class SecretManagerTest {

    @Mock
    private IKMSClient kmsClient;

    @Mock
    private IAuditLogger auditLogger;

    @Mock
    private DEKCache secretCache;

    private SecretManager secretManager;

    private static final BoundedContext CONTEXT = BoundedContext.PROFILE;
    private static final Environment ENV = Environment.DEV;
    private static final UUID KEK_ID = UUID.randomUUID();
    private static final Map<BoundedContext, UUID> KEK_IDS = Map.of(CONTEXT, KEK_ID);

    @BeforeEach
    void setUp() {
        secretManager = new SecretManager(kmsClient, auditLogger, secretCache, ENV, KEK_IDS);

        lenient().when(auditLogger.logKeyAccess(any()))
                .thenReturn(Result.failure(AuditError.of("NOOP", "no-op")));
        lenient().when(secretCache.get(any()))
                .thenReturn(Optional.empty());
    }

    // Secret storage in KMS

    @Test
    void storeSecret_callsKmsClientStoreSecret() {
        when(kmsClient.storeSecret(any(UUID.class), eq("my-token-value"), eq(KEK_ID)))
                .thenReturn(Result.success(Unit.unit()));

        secretManager.storeSecret("my-token", "my-token-value", SecretType.API_TOKEN, CONTEXT);

        verify(kmsClient).storeSecret(any(UUID.class), eq("my-token-value"), eq(KEK_ID));
    }

    @Test
    void storeSecret_returnsSecretId_onSuccess() {
        when(kmsClient.storeSecret(any(UUID.class), any(), eq(KEK_ID)))
                .thenReturn(Result.success(Unit.unit()));

        Result<UUID, KeyError> result = secretManager.storeSecret(
                "my-token", "my-token-value", SecretType.API_TOKEN, CONTEXT);

        assertTrue(result.isSuccess());
        assertNotNull(result.getValue().orElseThrow());
    }

    @Test
    void storeSecret_returnsFailure_whenKmsClientFails() {
        when(kmsClient.storeSecret(any(UUID.class), any(), eq(KEK_ID)))
                .thenReturn(Result.failure(KMSError.of("KMS_ERROR", "KMS unavailable")));

        Result<UUID, KeyError> result = secretManager.storeSecret(
                "my-token", "my-token-value", SecretType.API_TOKEN, CONTEXT);

        assertTrue(result.isFailure());
    }

    @Test
    void storeSecret_returnsFailure_whenNoKekForContext() {
        Result<UUID, KeyError> result = secretManager.storeSecret(
                "my-token", "my-token-value", SecretType.API_TOKEN, BoundedContext.CONSENT);

        assertTrue(result.isFailure());
        assertEquals(EncryptionErrorCodes.KEY_NOT_FOUND.code(),
                result.getError().orElseThrow().getCode());
    }

    @Test
    void getSecret_returnsSecretValue_fromKms_onCacheMiss() {
        UUID secretId = storeActiveSecret("db-pass", "secret123", SecretType.DATABASE_CREDENTIAL);

        when(secretCache.get(secretId)).thenReturn(Optional.empty());
        when(kmsClient.retrieveSecret(eq(secretId), eq(KEK_ID)))
                .thenReturn(Result.success("secret123"));

        Result<String, KeyError> result = secretManager.getSecret(secretId);

        assertTrue(result.isSuccess());
        assertEquals("secret123", result.getValue().orElseThrow());
        verify(kmsClient).retrieveSecret(eq(secretId), eq(KEK_ID));
    }

    @Test
    void getSecret_returnsSecretValue_fromCache_onCacheHit() {
        UUID secretId = storeActiveSecret("svc-secret", "cached-value", SecretType.SERVICE_SECRET);

        byte[] valueBytes = padOrTruncateTo32Bytes(
                "cached-value".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        DEK secretDek = DEK.of(valueBytes);
        DEKWithMetadata cacheEntry = DEKWithMetadata.builder()
                .dek(secretDek)
                .keyId(secretId)
                .kekId(KEK_ID)
                .context(CONTEXT)
                .environment(ENV)
                .algorithm(EncryptionAlgorithm.AES_256_GCM)
                .createdAt(Instant.now())
                .status(KeyStatus.ACTIVE)
                .build();

        when(secretCache.get(secretId)).thenReturn(Optional.of(cacheEntry));

        Result<String, KeyError> result = secretManager.getSecret(secretId);

        assertTrue(result.isSuccess());
        verify(kmsClient, never()).retrieveSecret(any(), any());
    }

    @Test
    void getSecret_returnsFailure_whenSecretNotFound() {
        Result<String, KeyError> result = secretManager.getSecret(UUID.randomUUID());

        assertTrue(result.isFailure());
        assertEquals(EncryptionErrorCodes.KEY_NOT_FOUND.code(),
                result.getError().orElseThrow().getCode());
    }

    @Test
    void getSecret_returnsFailure_whenKmsFails() {
        UUID secretId = storeActiveSecret("api-key", "value", SecretType.API_TOKEN);

        when(secretCache.get(secretId)).thenReturn(Optional.empty());
        when(kmsClient.retrieveSecret(eq(secretId), eq(KEK_ID)))
                .thenReturn(Result.failure(KMSError.of("KMS_ERROR", "KMS unavailable")));

        Result<String, KeyError> result = secretManager.getSecret(secretId);

        assertTrue(result.isFailure());
    }

    @Test
    void deleteSecret_removesFromKmsAndStore() {
        UUID secretId = storeActiveSecret("api-key", "value", SecretType.API_TOKEN);

        when(kmsClient.deleteSecret(secretId)).thenReturn(Result.success(Unit.unit()));

        Result<Unit, KeyError> deleteResult = secretManager.deleteSecret(secretId);
        assertTrue(deleteResult.isSuccess());
        verify(kmsClient).deleteSecret(secretId);

        Result<String, KeyError> getResult = secretManager.getSecret(secretId);
        assertTrue(getResult.isFailure());
        assertEquals(EncryptionErrorCodes.KEY_NOT_FOUND.code(),
                getResult.getError().orElseThrow().getCode());
    }

    @Test
    void deleteSecret_returnsFailure_whenSecretNotFound() {
        Result<Unit, KeyError> result = secretManager.deleteSecret(UUID.randomUUID());

        assertTrue(result.isFailure());
        assertEquals(EncryptionErrorCodes.KEY_NOT_FOUND.code(),
                result.getError().orElseThrow().getCode());
    }

    // Secret rotation schedules

    @Test
    void rotateSecret_storesNewSecretInKms() {
        UUID secretId = storeActiveSecret("api-key", "old-value", SecretType.API_TOKEN);

        when(kmsClient.storeSecret(any(UUID.class), eq("new-value"), eq(KEK_ID)))
                .thenReturn(Result.success(Unit.unit()));

        secretManager.rotateSecret(secretId, "new-value");

        verify(kmsClient).storeSecret(any(UUID.class), eq("new-value"), eq(KEK_ID));
    }

    @Test
    void rotateSecret_marksOldSecretAsRotated() {
        UUID secretId = storeActiveSecret("api-key", "old-value", SecretType.API_TOKEN);

        when(kmsClient.storeSecret(any(UUID.class), any(), eq(KEK_ID)))
                .thenReturn(Result.success(Unit.unit()));

        secretManager.rotateSecret(secretId, "new-value");

        Result<SecretMetadata, KeyError> metaResult = secretManager.getSecretMetadata(secretId);
        assertTrue(metaResult.isSuccess());
        assertEquals(KeyStatus.ROTATED, metaResult.getValue().orElseThrow().getStatus());
    }

    @Test
    void rotateSecret_newSecretIsActive() {
        UUID secretId = storeActiveSecret("api-key", "old-value", SecretType.API_TOKEN);

        when(kmsClient.storeSecret(any(UUID.class), any(), eq(KEK_ID)))
                .thenReturn(Result.success(Unit.unit()));

        Result<UUID, KeyError> rotateResult = secretManager.rotateSecret(secretId, "new-value");
        assertTrue(rotateResult.isSuccess());

        UUID newSecretId = rotateResult.getValue().orElseThrow();
        Result<SecretMetadata, KeyError> metaResult = secretManager.getSecretMetadata(newSecretId);
        assertTrue(metaResult.isSuccess());
        assertEquals(KeyStatus.ACTIVE, metaResult.getValue().orElseThrow().getStatus());
    }

    @Test
    void rotateSecret_invalidatesOldSecretFromCache() {
        UUID secretId = storeActiveSecret("api-key", "old-value", SecretType.API_TOKEN);

        when(kmsClient.storeSecret(any(UUID.class), any(), eq(KEK_ID)))
                .thenReturn(Result.success(Unit.unit()));

        secretManager.rotateSecret(secretId, "new-value");

        verify(secretCache).invalidate(secretId);
    }

    @Test
    void rotateSecret_returnsNewSecretId() {
        UUID secretId = storeActiveSecret("api-key", "old-value", SecretType.API_TOKEN);

        when(kmsClient.storeSecret(any(UUID.class), any(), eq(KEK_ID)))
                .thenReturn(Result.success(Unit.unit()));

        Result<UUID, KeyError> result = secretManager.rotateSecret(secretId, "new-value");

        assertTrue(result.isSuccess());
        assertNotEquals(secretId, result.getValue().orElseThrow());
    }

    @Test
    void rotateSecret_returnsFailure_whenSecretNotFound() {
        Result<UUID, KeyError> result = secretManager.rotateSecret(UUID.randomUUID(), "new-value");

        assertTrue(result.isFailure());
        assertEquals(EncryptionErrorCodes.KEY_NOT_FOUND.code(),
                result.getError().orElseThrow().getCode());
    }

    @Test
    void isDueForRotation_returnsFalse_forRecentSecret() {
        UUID secretId = storeActiveSecret("api-key", "value", SecretType.API_TOKEN);

        assertFalse(secretManager.isDueForRotation(secretId));
    }

    @Test
    void isDueForRotation_returnsTrue_forOldSecret() throws Exception {
        UUID secretId = storeActiveSecret("api-key", "value", SecretType.API_TOKEN);

        Field storeField = SecretManager.class.getDeclaredField("secretStore");
        storeField.setAccessible(true);
        @SuppressWarnings("unchecked")
        ConcurrentHashMap<UUID, SecretManager.SecretRecord> store =
                (ConcurrentHashMap<UUID, SecretManager.SecretRecord>) storeField.get(secretManager);

        SecretManager.SecretRecord oldRecord = store.get(secretId);
        SecretManager.SecretRecord agedRecord = new SecretManager.SecretRecord(
                oldRecord.secretId,
                oldRecord.secretName,
                oldRecord.secretType,
                oldRecord.context,
                oldRecord.environment,
                oldRecord.kekId,
                Instant.now().minus(91, ChronoUnit.DAYS),
                null,
                KeyStatus.ACTIVE
        );
        store.put(secretId, agedRecord);

        assertTrue(secretManager.isDueForRotation(secretId));
    }

    @Test
    void isDueForRotation_returnsFalse_forRotatedSecret() {
        UUID secretId = storeActiveSecret("api-key", "old-value", SecretType.API_TOKEN);

        when(kmsClient.storeSecret(any(UUID.class), any(), eq(KEK_ID)))
                .thenReturn(Result.success(Unit.unit()));

        secretManager.rotateSecret(secretId, "new-value");

        assertFalse(secretManager.isDueForRotation(secretId));
    }

    // Secret access logging

    @Test
    void storeSecret_logsKeyAccessEvent_withCorrectSecretType() {
        when(kmsClient.storeSecret(any(UUID.class), any(), eq(KEK_ID)))
                .thenReturn(Result.success(Unit.unit()));

        secretManager.storeSecret("my-token", "my-token-value", SecretType.API_TOKEN, CONTEXT);

        ArgumentCaptor<KeyAccessEvent> captor = ArgumentCaptor.forClass(KeyAccessEvent.class);
        verify(auditLogger).logKeyAccess(captor.capture());

        KeyAccessEvent event = captor.getValue();
        assertEquals("SECRET:API_TOKEN", event.getKeyType());
        assertEquals("store", event.getAccessType());
    }

    @Test
    void getSecret_logsKeyAccessEvent_onCacheMiss() {
        UUID secretId = storeActiveSecret("api-key", "value", SecretType.API_TOKEN);
        reset(auditLogger);
        lenient().when(auditLogger.logKeyAccess(any())).thenReturn(Result.failure(AuditError.of("NOOP", "no-op")));

        when(secretCache.get(secretId)).thenReturn(Optional.empty());
        when(kmsClient.retrieveSecret(eq(secretId), eq(KEK_ID)))
                .thenReturn(Result.success("value"));

        secretManager.getSecret(secretId);

        ArgumentCaptor<KeyAccessEvent> captor = ArgumentCaptor.forClass(KeyAccessEvent.class);
        verify(auditLogger).logKeyAccess(captor.capture());
        assertEquals("cache_miss", captor.getValue().getAccessType());
    }

    @Test
    void getSecret_logsKeyAccessEvent_onCacheHit() {
        UUID secretId = storeActiveSecret("api-key", "value", SecretType.API_TOKEN);
        reset(auditLogger);
        lenient().when(auditLogger.logKeyAccess(any())).thenReturn(Result.failure(AuditError.of("NOOP", "no-op")));

        byte[] valueBytes = padOrTruncateTo32Bytes(
                "value".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        DEKWithMetadata cacheEntry = DEKWithMetadata.builder()
                .dek(DEK.of(valueBytes))
                .keyId(secretId)
                .kekId(KEK_ID)
                .context(CONTEXT)
                .environment(ENV)
                .algorithm(EncryptionAlgorithm.AES_256_GCM)
                .createdAt(Instant.now())
                .status(KeyStatus.ACTIVE)
                .build();
        when(secretCache.get(secretId)).thenReturn(Optional.of(cacheEntry));

        secretManager.getSecret(secretId);

        ArgumentCaptor<KeyAccessEvent> captor = ArgumentCaptor.forClass(KeyAccessEvent.class);
        verify(auditLogger).logKeyAccess(captor.capture());
        assertEquals("cache_hit", captor.getValue().getAccessType());
    }

    @Test
    void rotateSecret_logsKeyAccessEvent_withRotateAccessType() {
        UUID secretId = storeActiveSecret("api-key", "old-value", SecretType.API_TOKEN);
        reset(auditLogger);
        lenient().when(auditLogger.logKeyAccess(any())).thenReturn(Result.failure(AuditError.of("NOOP", "no-op")));

        when(kmsClient.storeSecret(any(UUID.class), any(), eq(KEK_ID)))
                .thenReturn(Result.success(Unit.unit()));

        secretManager.rotateSecret(secretId, "new-value");

        ArgumentCaptor<KeyAccessEvent> captor = ArgumentCaptor.forClass(KeyAccessEvent.class);
        verify(auditLogger).logKeyAccess(captor.capture());
        assertEquals("rotate", captor.getValue().getAccessType());
    }

    @Test
    void deleteSecret_logsKeyAccessEvent_withDeleteAccessType() {
        UUID secretId = storeActiveSecret("api-key", "value", SecretType.API_TOKEN);
        reset(auditLogger);
        lenient().when(auditLogger.logKeyAccess(any())).thenReturn(Result.failure(AuditError.of("NOOP", "no-op")));

        when(kmsClient.deleteSecret(secretId)).thenReturn(Result.success(Unit.unit()));

        secretManager.deleteSecret(secretId);

        ArgumentCaptor<KeyAccessEvent> captor = ArgumentCaptor.forClass(KeyAccessEvent.class);
        verify(auditLogger).logKeyAccess(captor.capture());
        assertEquals("delete", captor.getValue().getAccessType());
    }

    @Test
    void storeSecret_logsFailedAccess_whenKmsFails() {
        when(kmsClient.storeSecret(any(UUID.class), any(), eq(KEK_ID)))
                .thenReturn(Result.failure(KMSError.of("KMS_ERROR", "KMS unavailable")));

        secretManager.storeSecret("my-token", "my-token-value", SecretType.API_TOKEN, CONTEXT);

        ArgumentCaptor<KeyAccessEvent> captor = ArgumentCaptor.forClass(KeyAccessEvent.class);
        verify(auditLogger).logKeyAccess(captor.capture());
        assertFalse(captor.getValue().isSuccess());
    }

    // Helpers

    /**
     * Stores a secret via the real storeSecret method (requires kmsClient stub).
     * Returns the assigned secretId.
     */
    private UUID storeActiveSecret(String name, String value, SecretType type) {
        when(kmsClient.storeSecret(any(UUID.class), eq(value), eq(KEK_ID)))
                .thenReturn(Result.success(Unit.unit()));
        Result<UUID, KeyError> result = secretManager.storeSecret(name, value, type, CONTEXT);
        assertTrue(result.isSuccess(), "Helper storeActiveSecret failed: " + result.getError());
        return result.getValue().orElseThrow();
    }

    private static byte[] padOrTruncateTo32Bytes(byte[] input) {
        if (input.length == 32) return input;
        byte[] result = new byte[32];
        System.arraycopy(input, 0, result, 0, Math.min(input.length, 32));
        return result;
    }
}
