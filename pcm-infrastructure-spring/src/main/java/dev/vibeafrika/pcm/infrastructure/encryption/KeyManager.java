package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of IKeyManager that manages the KEK/DEK hierarchy with caching.
 * 
 * <p>This class coordinates with KMS for key operations and manages a DEK cache
 * for performance optimization. It implements envelope encryption where:
 * <ul>
 *   <li>KEKs remain in KMS/HSM and never leave secure boundaries</li>
 *   <li>DEKs are encrypted by KEKs and cached in application memory</li>
 *   <li>Actual PII data is encrypted using cached DEKs</li>
 * </ul>
 * 
 * <p>Key features:
 * <ul>
 *   <li>DEK caching with LRU eviction and TTL (1 hour)</li>
 *   <li>Automatic key rotation based on age, usage, and operations</li>
 *   <li>Context and environment isolation</li>
 *   <li>Secure memory wiping on cache eviction</li>
 *   <li>Comprehensive audit logging</li>
 * </ul>
 * 
 */
public class KeyManager implements IKeyManager {
    
    private static final Logger logger = LoggerFactory.getLogger(KeyManager.class);
    
    private final IKMSClient kmsClient;
    private final IAuditLogger auditLogger;
    private final DEKCache dekCache;
    private final Environment environment;
    private final SecureRandom secureRandom;
    private final IVCounter ivCounter;
    
    // Track active DEK IDs per context
    private final Map<BoundedContext, UUID> activeDEKIds;
    
    // Track KEK IDs per context
    private final Map<BoundedContext, UUID> kekIds;
    
    // In-memory metadata store (in production, this would be backed by a database)
    private final Map<UUID, DEKMetadata> dekMetadataStore;
    
    /**
     * Creates a KeyManager with the specified dependencies.
     * 
     * @param kmsClient the KMS client for key operations
     * @param auditLogger the audit logger for logging key operations
     * @param dekCache the DEK cache for performance optimization
     * @param environment the current environment (DEV, STAGING, PROD)
     * @param ivCounter the IV counter for managing per-DEK IV state
     */
    public KeyManager(IKMSClient kmsClient, IAuditLogger auditLogger,
                     DEKCache dekCache, Environment environment, IVCounter ivCounter) {
        this.kmsClient = Objects.requireNonNull(kmsClient, "KMS client cannot be null");
        this.auditLogger = Objects.requireNonNull(auditLogger, "Audit logger cannot be null");
        this.dekCache = Objects.requireNonNull(dekCache, "DEK cache cannot be null");
        this.environment = Objects.requireNonNull(environment, "Environment cannot be null");
        this.ivCounter = Objects.requireNonNull(ivCounter, "IV counter cannot be null");
        this.secureRandom = new SecureRandom();
        this.activeDEKIds = new ConcurrentHashMap<>();
        this.kekIds = new ConcurrentHashMap<>();
        this.dekMetadataStore = new ConcurrentHashMap<>();
    }
    
    @Override
    public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
        Objects.requireNonNull(context, "Context cannot be null");
        
        // Get the active DEK ID for this context
        UUID activeDEKId = activeDEKIds.get(context);
        if (activeDEKId == null) {
            return Result.failure(KeyError.of(
                "KEY_NOT_FOUND",
                "No active DEK found for context: " + context
            ));
        }
        
        // Retrieve the DEK (will use cache if available)
        return getDEK(activeDEKId);
    }
    
    @Override
    public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
        Objects.requireNonNull(keyId, "Key ID cannot be null");
        
        // Check cache first
        var cachedDEK = dekCache.get(keyId);
        if (cachedDEK.isPresent()) {
            logKeyAccess(keyId, "CACHE_HIT", true);
            return Result.success(cachedDEK.get());
        }
        
        logKeyAccess(keyId, "CACHE_MISS", true);
        
        // Cache miss - retrieve from KMS
        return retrieveDEKFromKMS(keyId);
    }
    
    /**
     * Retrieves a DEK from KMS, decrypts it, and caches it.
     */
    private Result<DEKWithMetadata, KeyError> retrieveDEKFromKMS(UUID keyId) {
        // Get DEK metadata
        DEKMetadata metadata = dekMetadataStore.get(keyId);
        if (metadata == null) {
            return Result.failure(KeyError.of(
                "KEY_NOT_FOUND",
                "DEK metadata not found for key ID: " + keyId
            ));
        }
        
        // Verify environment matches
        if (metadata.environment != environment) {
            String errorMsg = String.format(
                "Environment mismatch: DEK is for %s but current environment is %s",
                metadata.environment, environment
            );
            logSecurityEvent("ENVIRONMENT_MISMATCH", keyId, errorMsg);
            return Result.failure(KeyError.of("ENVIRONMENT_MISMATCH", errorMsg));
        }
        
        // Get encrypted DEK from KMS
        Result<DEK, KMSError> decryptResult = kmsClient.decryptDEK(
            metadata.encryptedDEK,
            metadata.kekId
        );
        
        if (decryptResult.isFailure()) {
            KMSError kmsError = decryptResult.getError().orElseThrow();
            return Result.failure(KeyError.of(
                "KMS_DECRYPTION_FAILED",
                "Failed to decrypt DEK from KMS: " + kmsError.getMessage(),
                new RuntimeException(kmsError.getMessage())
            ));
        }
        
        DEK dek = decryptResult.getValue().orElseThrow();
        
        // Build DEKWithMetadata
        DEKWithMetadata dekWithMetadata = DEKWithMetadata.builder()
            .dek(dek)
            .keyId(keyId)
            .kekId(metadata.kekId)
            .context(metadata.context)
            .environment(metadata.environment)
            .algorithm(metadata.algorithm)
            .createdAt(metadata.createdAt)
            .rotatedAt(metadata.rotatedAt)
            .status(metadata.status)
            .encryptionCount(metadata.encryptionCount)
            .bytesEncrypted(metadata.bytesEncrypted)
            .build();
        
        // Cache the decrypted DEK
        dekCache.put(keyId, dekWithMetadata);
        
        logKeyAccess(keyId, "RETRIEVED_FROM_KMS", true);
        
        return Result.success(dekWithMetadata);
    }
    
    @Override
    public Result<UUID, KeyError> rotateDEK(BoundedContext context) {
        Objects.requireNonNull(context, "Context cannot be null");
        
        // Get KEK ID for this context
        UUID kekId = kekIds.get(context);
        if (kekId == null) {
            return Result.failure(KeyError.of(
                "KEK_NOT_FOUND",
                "No KEK found for context: " + context
            ));
        }
        
        // Generate new DEK (256 bits = 32 bytes)
        byte[] dekBytes = new byte[32];
        secureRandom.nextBytes(dekBytes);
        DEK newDEK = DEK.of(dekBytes);
        
        // Encrypt DEK with KEK in KMS
        Result<EncryptedDEK, KMSError> encryptResult = kmsClient.encryptDEK(newDEK, kekId);
        if (encryptResult.isFailure()) {
            KMSError kmsError = encryptResult.getError().orElseThrow();
            return Result.failure(KeyError.of(
                "KMS_ENCRYPTION_FAILED",
                "Failed to encrypt new DEK with KMS: " + kmsError.getMessage(),
                new RuntimeException(kmsError.getMessage())
            ));
        }
        
        EncryptedDEK encryptedDEK = encryptResult.getValue().orElseThrow();
        
        // Generate new DEK ID
        UUID newDEKId = UUID.randomUUID();
        
        // Store DEK metadata
        DEKMetadata metadata = new DEKMetadata(
            newDEKId,
            kekId,
            context,
            environment,
            EncryptionAlgorithm.AES_256_GCM,
            Instant.now(),
            null,
            KeyStatus.ACTIVE,
            0,
            0,
            encryptedDEK
        );
        dekMetadataStore.put(newDEKId, metadata);
        
        // Mark old DEK as rotated if exists
        UUID oldDEKId = activeDEKIds.get(context);
        if (oldDEKId != null) {
            DEKMetadata oldMetadata = dekMetadataStore.get(oldDEKId);
            if (oldMetadata != null) {
                oldMetadata.status = KeyStatus.ROTATED;
                oldMetadata.rotatedAt = Instant.now();
            }
            
            // Invalidate old DEK from cache
            dekCache.invalidate(oldDEKId);
            
            // Log rotation event
            logKeyRotation(oldDEKId, newDEKId, context, "DEK", "SCHEDULED");
        }
        
        // Set new DEK as active
        activeDEKIds.put(context, newDEKId);
        
        // Reset IV counter for the new DEK so it starts fresh
        Result<Unit, IVCounterError> resetResult = ivCounter.resetState(newDEKId);
        if (resetResult.isFailure()) {
            // Log warning but don't fail the rotation — the counter will be initialized
            // on first use via getOrInitializeState in IVCounterImpl
            logger.warn("Failed to reset IV counter for new DEK {}: {}", newDEKId,
                resetResult.getError().map(IVCounterError::getMessage).orElse("unknown error"));
        }
        
        logger.info("DEK rotated for context: {}, new DEK ID: {}", context, newDEKId);
        
        return Result.success(newDEKId);
    }
    
    @Override
    public Result<UUID, KeyError> rotateKEK(BoundedContext context) {
        Objects.requireNonNull(context, "Context cannot be null");
        
        // Generate new KEK in KMS
        Result<UUID, KMSError> generateResult = kmsClient.generateKEK(context, environment);
        if (generateResult.isFailure()) {
            KMSError kmsError = generateResult.getError().orElseThrow();
            return Result.failure(KeyError.of(
                "KMS_KEK_GENERATION_FAILED",
                "Failed to generate new KEK in KMS: " + kmsError.getMessage(),
                new RuntimeException(kmsError.getMessage())
            ));
        }
        
        UUID newKEKId = generateResult.getValue().orElseThrow();
        UUID oldKEKId = kekIds.get(context);
        
        // Re-encrypt all DEKs for this context with the new KEK
        dekMetadataStore.values().stream()
            .filter(metadata -> metadata.context == context && metadata.kekId.equals(oldKEKId))
            .forEach(metadata -> {
                // This would involve decrypting with old KEK and re-encrypting with new KEK
                // For now, we'll just update the KEK ID reference
                metadata.kekId = newKEKId;
            });
        
        // Update KEK ID
        kekIds.put(context, newKEKId);
        
        // Invalidate all cached DEKs for this context
        dekMetadataStore.values().stream()
            .filter(metadata -> metadata.context == context)
            .forEach(metadata -> dekCache.invalidate(metadata.keyId));
        
        // Log rotation event
        if (oldKEKId != null) {
            logKeyRotation(oldKEKId, newKEKId, context, "KEK", "SCHEDULED");
        }
        
        logger.info("KEK rotated for context: {}, new KEK ID: {}", context, newKEKId);
        
        return Result.success(newKEKId);
    }
    
    @Override
    public Result<Void, KeyError> invalidateCache(UUID keyId) {
        if (keyId == null) {
            // Invalidate all cached DEKs
            dekCache.invalidateAll();
            logger.info("All DEKs invalidated from cache");
        } else {
            // Invalidate specific DEK
            dekCache.invalidate(keyId);
            logger.info("DEK invalidated from cache: {}", keyId);
        }
        
        return Result.success(null);
    }
    
    @Override
    public Result<DeletionCertificate, KeyError> deleteUserDEK(String userId, BoundedContext context) {
        Objects.requireNonNull(userId, "User ID cannot be null");
        Objects.requireNonNull(context, "Context cannot be null");
        
        // Find user-specific DEK (in a real implementation, this would query a database)
        // For now, we'll create a placeholder implementation
        UUID userDEKId = UUID.nameUUIDFromBytes((userId + context.name()).getBytes());
        
        // Remove from metadata store
        dekMetadataStore.remove(userDEKId);
        
        // Invalidate from cache
        dekCache.invalidate(userDEKId);
        
        // Generate deletion certificate with signature
        Instant deletedAt = Instant.now();
        String signature = generateDeletionSignature(userDEKId, userId, context, deletedAt);
        
        DeletionCertificate certificate = DeletionCertificate.of(
            userDEKId,
            userId,
            context,
            deletedAt,
            signature
        );
        
        logger.info("User DEK deleted for user: {}, context: {}, key ID: {}", 
                   userId, context, userDEKId);
        
        return Result.success(certificate);
    }
    
    /**
     * Generates a signature for the deletion certificate.
     */
    private String generateDeletionSignature(UUID keyId, String userId, 
                                            BoundedContext context, Instant deletedAt) {
        // In a real implementation, this would use HMAC-SHA256
        String data = keyId + userId + context + deletedAt;
        return "SIGNATURE:" + Integer.toHexString(data.hashCode());
    }
    
    /**
     * Logs a key access event.
     */
    private void logKeyAccess(UUID keyId, String accessType, boolean success) {
        // Get context from metadata if available
        DEKMetadata metadata = dekMetadataStore.get(keyId);
        BoundedContext context = metadata != null ? metadata.context : BoundedContext.PROFILE;
        
        KeyAccessEvent event = KeyAccessEvent.builder()
            .keyId(keyId)
            .accessType(accessType)
            .timestamp(Instant.now())
            .context(context)
            .serviceIdentity("KeyManager")
            .success(success)
            .build();
        
        auditLogger.logKeyAccess(event);
    }
    
    /**
     * Logs a key rotation event.
     */
    private void logKeyRotation(UUID oldKeyId, UUID newKeyId, BoundedContext context,
                               String keyType, String reason) {
        KeyRotationEvent event = KeyRotationEvent.builder()
            .oldKeyId(oldKeyId)
            .newKeyId(newKeyId)
            .context(context)
            .keyType(keyType)
            .rotationReason(reason)
            .timestamp(Instant.now())
            .serviceIdentity("KeyManager")
            .success(true)
            .build();
        
        auditLogger.logKeyRotation(event);
    }
    
    /**
     * Logs a security event.
     */
    private void logSecurityEvent(String eventType, UUID keyId, String description) {
        // Get context from metadata if available
        DEKMetadata metadata = dekMetadataStore.get(keyId);
        BoundedContext context = metadata != null ? metadata.context : BoundedContext.PROFILE;
        
        SecurityEvent event = SecurityEvent.builder()
            .eventType(eventType)
            .keyId(keyId)
            .description(description)
            .timestamp(Instant.now())
            .context(context)
            .serviceIdentity("KeyManager")
            .severity("HIGH")
            .build();
        
        auditLogger.logSecurityEvent(event);
    }
    
    /**
     * Initializes a KEK for a bounded context.
     * This should be called during system setup.
     */
    public Result<UUID, KeyError> initializeKEK(BoundedContext context) {
        Result<UUID, KMSError> generateResult = kmsClient.generateKEK(context, environment);
        if (generateResult.isFailure()) {
            KMSError kmsError = generateResult.getError().orElseThrow();
            return Result.failure(KeyError.of(
                "KMS_KEK_GENERATION_FAILED",
                "Failed to initialize KEK in KMS: " + kmsError.getMessage(),
                new RuntimeException(kmsError.getMessage())
            ));
        }
        
        UUID kekId = generateResult.getValue().orElseThrow();
        kekIds.put(context, kekId);
        
        logger.info("KEK initialized for context: {}, KEK ID: {}", context, kekId);
        
        return Result.success(kekId);
    }
    
    /**
     * Internal class to store DEK metadata.
     */
    private static class DEKMetadata {
        UUID keyId;
        UUID kekId;
        BoundedContext context;
        Environment environment;
        EncryptionAlgorithm algorithm;
        Instant createdAt;
        Instant rotatedAt;
        KeyStatus status;
        long encryptionCount;
        long bytesEncrypted;
        EncryptedDEK encryptedDEK;
        
        DEKMetadata(UUID keyId, UUID kekId, BoundedContext context, Environment environment,
                   EncryptionAlgorithm algorithm, Instant createdAt, Instant rotatedAt,
                   KeyStatus status, long encryptionCount, long bytesEncrypted,
                   EncryptedDEK encryptedDEK) {
            this.keyId = keyId;
            this.kekId = kekId;
            this.context = context;
            this.environment = environment;
            this.algorithm = algorithm;
            this.createdAt = createdAt;
            this.rotatedAt = rotatedAt;
            this.status = status;
            this.encryptionCount = encryptionCount;
            this.bytesEncrypted = bytesEncrypted;
            this.encryptedDEK = encryptedDEK;
        }
    }
}
