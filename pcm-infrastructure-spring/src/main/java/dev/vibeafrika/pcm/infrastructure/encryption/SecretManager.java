package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of {@link ISecretManager} that stores non-cryptographic secrets
 * (API tokens, database credentials, service secrets) in KMS with the same
 * encryption standards, caching, and access control as DEKs.
 *
 * <p>Rotation schedules:
 * <ul>
 *   <li>API tokens: 90 days</li>
 *   <li>Database credentials: 90 days (quarterly)</li>
 *   <li>Service secrets: 90 days (quarterly)</li>
 * </ul>
 *
 * <p>All secret access is audit-logged via {@link IAuditLogger} with the same
 * detail as key access.
 */
public class SecretManager implements ISecretManager {

    private static final Logger logger = LoggerFactory.getLogger(SecretManager.class);

    /** Rotation interval in days for all secret types. */
    static final long ROTATION_INTERVAL_DAYS = 90L;

    private final IKMSClient kmsClient;
    private final IAuditLogger auditLogger;
    private final DEKCache secretCache; // reuse DEKCache TTL/LRU for secret values
    private final Environment environment;
    private final Map<BoundedContext, UUID> kekIds;

    // In-memory metadata store (production: backed by a database)
    final Map<UUID, SecretRecord> secretStore = new ConcurrentHashMap<>();

    /**
     * @param kmsClient   KMS client for secret storage/retrieval
     * @param auditLogger audit logger for access logging
     * @param secretCache shared DEK cache reused for secret caching (same TTL/LRU policy)
     * @param environment current deployment environment
     * @param kekIds      KEK IDs per bounded context (shared with KeyManager)
     */
    public SecretManager(IKMSClient kmsClient,
                         IAuditLogger auditLogger,
                         DEKCache secretCache,
                         Environment environment,
                         Map<BoundedContext, UUID> kekIds) {
        this.kmsClient = Objects.requireNonNull(kmsClient, "KMS client cannot be null");
        this.auditLogger = Objects.requireNonNull(auditLogger, "Audit logger cannot be null");
        this.secretCache = Objects.requireNonNull(secretCache, "Secret cache cannot be null");
        this.environment = Objects.requireNonNull(environment, "Environment cannot be null");
        this.kekIds = Objects.requireNonNull(kekIds, "KEK IDs map cannot be null");
    }

    @Override
    public Result<UUID, KeyError> storeSecret(String secretName, String secretValue,
                                               SecretType secretType, BoundedContext context) {
        Objects.requireNonNull(secretName, "Secret name cannot be null");
        Objects.requireNonNull(secretValue, "Secret value cannot be null");
        Objects.requireNonNull(secretType, "Secret type cannot be null");
        Objects.requireNonNull(context, "Context cannot be null");

        UUID kekId = kekIds.get(context);
        if (kekId == null) {
            return Result.failure(KeyError.of(
                EncryptionErrorCodes.KEY_NOT_FOUND,
                "No KEK found for context: " + context + ". Initialize KEK before storing secrets."
            ));
        }

        UUID secretId = UUID.randomUUID();

        Result<Unit, KMSError> storeResult = kmsClient.storeSecret(secretId, secretValue, kekId);
        if (storeResult.isFailure()) {
            KMSError kmsError = storeResult.getError().orElseThrow();
            logSecretAccess(secretId, secretName, secretType, context, "store", false);
            return Result.failure(KeyError.of(
                EncryptionErrorCodes.KMS_UNAVAILABLE,
                "Failed to store secret in KMS: " + kmsError.getMessage()
            ));
        }

        SecretRecord record = new SecretRecord(
            secretId, secretName, secretType, context, environment, kekId,
            Instant.now(), null, KeyStatus.ACTIVE
        );
        secretStore.put(secretId, record);

        logSecretAccess(secretId, secretName, secretType, context, "store", true);
        logger.info("Secret stored: id={}, name={}, type={}, context={}", secretId, secretName, secretType, context);
        return Result.success(secretId);
    }

    @Override
    public Result<String, KeyError> getSecret(UUID secretId) {
        Objects.requireNonNull(secretId, "Secret ID cannot be null");

        SecretRecord record = secretStore.get(secretId);
        if (record == null) {
            return Result.failure(KeyError.of(
                EncryptionErrorCodes.KEY_NOT_FOUND,
                "Secret not found: " + secretId
            ));
        }

        // Cache lookup — reuse DEKCache keyed by secretId (same TTL/LRU policy)
        java.util.Optional<DEKWithMetadata> cachedOpt = secretCache.get(secretId);
        if (cachedOpt.isPresent()) {
            // The secret value is stored as the DEK bytes encoded as UTF-8 in the cache entry.
            // We use a thin wrapper: the DEK bytes hold the secret value bytes.
            logSecretAccess(secretId, record.secretName, record.secretType, record.context, "cache_hit", true);
            return Result.success(new String(cachedOpt.get().getDek().getKeyMaterial(), java.nio.charset.StandardCharsets.UTF_8));
        }

        // Cache miss — fetch from KMS
        Result<String, KMSError> fetchResult = kmsClient.retrieveSecret(secretId, record.kekId);
        if (fetchResult.isFailure()) {
            KMSError kmsError = fetchResult.getError().orElseThrow();
            logSecretAccess(secretId, record.secretName, record.secretType, record.context, "cache_miss_failed", false);
            return Result.failure(KeyError.of(
                EncryptionErrorCodes.KEY_UNAVAILABLE,
                "Failed to retrieve secret from KMS: " + kmsError.getMessage()
            ));
        }

        String secretValue = fetchResult.getValue().orElseThrow();

        // Cache the secret value using DEKCache (same TTL/LRU)
        byte[] valueBytes = secretValue.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        DEK secretDek = DEK.of(padOrTruncateTo32Bytes(valueBytes));
        DEKWithMetadata cacheEntry = DEKWithMetadata.builder()
            .dek(secretDek)
            .keyId(secretId)
            .kekId(record.kekId)
            .context(record.context)
            .environment(record.environment)
            .algorithm(EncryptionAlgorithm.AES_256_GCM)
            .createdAt(record.createdAt)
            .status(record.status)
            .build();
        secretCache.put(secretId, cacheEntry);

        logSecretAccess(secretId, record.secretName, record.secretType, record.context, "cache_miss", true);
        return Result.success(secretValue);
    }

    @Override
    public Result<UUID, KeyError> rotateSecret(UUID secretId, String newSecretValue) {
        Objects.requireNonNull(secretId, "Secret ID cannot be null");
        Objects.requireNonNull(newSecretValue, "New secret value cannot be null");

        SecretRecord oldRecord = secretStore.get(secretId);
        if (oldRecord == null) {
            return Result.failure(KeyError.of(
                EncryptionErrorCodes.KEY_NOT_FOUND,
                "Secret not found for rotation: " + secretId
            ));
        }

        // Store new secret value in KMS
        UUID newSecretId = UUID.randomUUID();
        Result<Unit, KMSError> storeResult = kmsClient.storeSecret(newSecretId, newSecretValue, oldRecord.kekId);
        if (storeResult.isFailure()) {
            KMSError kmsError = storeResult.getError().orElseThrow();
            logSecretAccess(secretId, oldRecord.secretName, oldRecord.secretType, oldRecord.context, "rotate_failed", false);
            return Result.failure(KeyError.of(
                EncryptionErrorCodes.KEY_ROTATION_FAILED,
                "Failed to store rotated secret in KMS: " + kmsError.getMessage()
            ));
        }

        // Mark old secret as ROTATED
        SecretRecord rotatedRecord = new SecretRecord(
            oldRecord.secretId, oldRecord.secretName, oldRecord.secretType,
            oldRecord.context, oldRecord.environment, oldRecord.kekId,
            oldRecord.createdAt, Instant.now(), KeyStatus.ROTATED
        );
        secretStore.put(secretId, rotatedRecord);

        // Register new secret as ACTIVE
        SecretRecord newRecord = new SecretRecord(
            newSecretId, oldRecord.secretName, oldRecord.secretType,
            oldRecord.context, oldRecord.environment, oldRecord.kekId,
            Instant.now(), null, KeyStatus.ACTIVE
        );
        secretStore.put(newSecretId, newRecord);

        // Invalidate old secret from cache
        secretCache.invalidate(secretId);

        logSecretAccess(secretId, oldRecord.secretName, oldRecord.secretType, oldRecord.context, "rotate", true);
        logger.info("Secret rotated: oldId={}, newId={}, name={}, type={}, context={}",
            secretId, newSecretId, oldRecord.secretName, oldRecord.secretType, oldRecord.context);
        return Result.success(newSecretId);
    }

    @Override
    public Result<Unit, KeyError> deleteSecret(UUID secretId) {
        Objects.requireNonNull(secretId, "Secret ID cannot be null");

        SecretRecord record = secretStore.get(secretId);
        if (record == null) {
            return Result.failure(KeyError.of(
                EncryptionErrorCodes.KEY_NOT_FOUND,
                "Secret not found for deletion: " + secretId
            ));
        }

        Result<Unit, KMSError> deleteResult = kmsClient.deleteSecret(secretId);
        if (deleteResult.isFailure()) {
            KMSError kmsError = deleteResult.getError().orElseThrow();
            logSecretAccess(secretId, record.secretName, record.secretType, record.context, "delete_failed", false);
            return Result.failure(KeyError.of(
                EncryptionErrorCodes.KMS_UNAVAILABLE,
                "Failed to delete secret from KMS: " + kmsError.getMessage()
            ));
        }

        secretStore.remove(secretId);
        secretCache.invalidate(secretId);

        logSecretAccess(secretId, record.secretName, record.secretType, record.context, "delete", true);
        logger.info("Secret deleted: id={}, name={}, type={}, context={}",
            secretId, record.secretName, record.secretType, record.context);
        return Result.success(Unit.unit());
    }

    @Override
    public Result<SecretMetadata, KeyError> getSecretMetadata(UUID secretId) {
        Objects.requireNonNull(secretId, "Secret ID cannot be null");

        SecretRecord record = secretStore.get(secretId);
        if (record == null) {
            return Result.failure(KeyError.of(
                EncryptionErrorCodes.KEY_NOT_FOUND,
                "Secret not found: " + secretId
            ));
        }

        SecretMetadata metadata = SecretMetadata.builder()
            .secretId(record.secretId)
            .secretName(record.secretName)
            .secretType(record.secretType)
            .context(record.context)
            .environment(record.environment)
            .createdAt(record.createdAt)
            .rotatedAt(record.rotatedAt)
            .status(record.status)
            .build();

        return Result.success(metadata);
    }

    /**
     * Returns true if the secret is due for rotation based on its type and creation date.
     * All secret types rotate every {@value #ROTATION_INTERVAL_DAYS} days.
     */
    public boolean isDueForRotation(UUID secretId) {
        SecretRecord record = secretStore.get(secretId);
        if (record == null || record.status != KeyStatus.ACTIVE) {
            return false;
        }
        Instant rotationDue = record.createdAt.plus(
            java.time.Duration.ofDays(ROTATION_INTERVAL_DAYS));
        return Instant.now().isAfter(rotationDue);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Logs secret access via the audit logger.
     * The secret value is NEVER included in the log entry.
     */
    private void logSecretAccess(UUID secretId, String secretName, SecretType secretType,
                                  BoundedContext context, String accessType, boolean success) {
        try {
            KeyAccessEvent event = KeyAccessEvent.builder()
                .timestamp(Instant.now())
                .context(context)
                .serviceIdentity("SecretManager")
                .keyId(secretId)
                .keyType("SECRET:" + secretType.name())
                .accessType(accessType)
                .success(success)
                .metadata(Map.of("secretName", secretName))
                .build();
            auditLogger.logKeyAccess(event);
        } catch (Exception e) {
            logger.warn("Failed to log secret access for secretId={}: {}", secretId, e.getMessage());
        }
    }

    /**
     * Pads or truncates a byte array to exactly 32 bytes for use as a DEK wrapper.
     * This is only used for the cache entry; the actual secret value is stored as a String.
     */
    private static byte[] padOrTruncateTo32Bytes(byte[] input) {
        if (input.length == 32) return input;
        byte[] result = new byte[32];
        System.arraycopy(input, 0, result, 0, Math.min(input.length, 32));
        return result;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal record
    // ─────────────────────────────────────────────────────────────────────────

    /** Internal metadata record for a stored secret. */
    static final class SecretRecord {
        final UUID secretId;
        final String secretName;
        final SecretType secretType;
        final BoundedContext context;
        final Environment environment;
        final UUID kekId;
        final Instant createdAt;
        final Instant rotatedAt;
        final KeyStatus status;

        SecretRecord(UUID secretId, String secretName, SecretType secretType,
                     BoundedContext context, Environment environment, UUID kekId,
                     Instant createdAt, Instant rotatedAt, KeyStatus status) {
            this.secretId = secretId;
            this.secretName = secretName;
            this.secretType = secretType;
            this.context = context;
            this.environment = environment;
            this.kekId = kekId;
            this.createdAt = createdAt;
            this.rotatedAt = rotatedAt;
            this.status = status;
        }
    }
}
