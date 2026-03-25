package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

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

    /** Optional circuit breaker; null when not configured. */
    private final KMSCircuitBreaker circuitBreaker;

    /** Epoch-ms timestamp when KMS first became unavailable; 0 = currently available. */
    private final AtomicLong kmsUnavailableSince = new AtomicLong(0L);

    /** Threshold after which an alert is raised for prolonged KMS unavailability (2 minutes). */
    private static final long KMS_ALERT_THRESHOLD_MS = 120_000L;
    
    // Track active DEK IDs per context
    private final Map<BoundedContext, UUID> activeDEKIds;
    
    // Track KEK IDs per context
    private final Map<BoundedContext, UUID> kekIds;
    
    // In-memory metadata store (in production, this would be backed by a database)
    private final Map<UUID, DEKMetadata> dekMetadataStore;
    
    // In-memory KEK metadata store (in production, this would be backed by a database)
    private final Map<UUID, KEKMetadata> kekMetadataStore;

    // Blind index key (32 bytes / 256 bits), stored separately from DEKs
    private volatile byte[] blindIndexKey;
    
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
        this(kmsClient, auditLogger, dekCache, environment, ivCounter, null);
    }

    /**
     * Creates a KeyManager with the specified dependencies and an optional circuit breaker.
     *
     * @param kmsClient      the KMS client for key operations
     * @param auditLogger    the audit logger for logging key operations
     * @param dekCache       the DEK cache for performance optimization
     * @param environment    the current environment (DEV, STAGING, PROD)
     * @param ivCounter      the IV counter for managing per-DEK IV state
     * @param circuitBreaker optional circuit breaker wrapping the KMS client (may be null)
     */
    public KeyManager(IKMSClient kmsClient, IAuditLogger auditLogger,
                     DEKCache dekCache, Environment environment, IVCounter ivCounter,
                     KMSCircuitBreaker circuitBreaker) {
        this.kmsClient = Objects.requireNonNull(kmsClient, "KMS client cannot be null");
        this.auditLogger = Objects.requireNonNull(auditLogger, "Audit logger cannot be null");
        this.dekCache = Objects.requireNonNull(dekCache, "DEK cache cannot be null");
        this.environment = Objects.requireNonNull(environment, "Environment cannot be null");
        this.ivCounter = Objects.requireNonNull(ivCounter, "IV counter cannot be null");
        this.circuitBreaker = circuitBreaker; // nullable
        this.secureRandom = new SecureRandom();
        this.activeDEKIds = new ConcurrentHashMap<>();
        this.kekIds = new ConcurrentHashMap<>();
        this.dekMetadataStore = new ConcurrentHashMap<>();
        this.kekMetadataStore = new ConcurrentHashMap<>();
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
        Result<DEK, KMSError> decryptResult = effectiveKmsClient().decryptDEK(
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
        
        // Reject new encryption when circuit breaker is in read-only mode
        if (circuitBreaker != null && circuitBreaker.isReadOnly()) {
            return Result.failure(KeyError.of(
                "KMS_UNAVAILABLE",
                "KMS is unavailable: circuit breaker is open"
            ));
        }

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
        Result<EncryptedDEK, KMSError> encryptResult = effectiveKmsClient().encryptDEK(newDEK, kekId);
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
        
        UUID oldKEKId = kekIds.get(context);
        
        // Generate new KEK in KMS
        Result<UUID, KMSError> generateResult = effectiveKmsClient().generateKEK(context, environment);
        if (generateResult.isFailure()) {
            KMSError kmsError = generateResult.getError().orElseThrow();
            return Result.failure(KeyError.of(
                "KMS_KEK_GENERATION_FAILED",
                "Failed to generate new KEK in KMS: " + kmsError.getMessage(),
                new RuntimeException(kmsError.getMessage())
            ));
        }
        
        UUID newKEKId = generateResult.getValue().orElseThrow();
        
        // Retrieve all DEKs encrypted with the old KEK and re-encrypt each with the new KEK
        if (oldKEKId != null) {
            for (DEKMetadata metadata : dekMetadataStore.values()) {
                if (metadata.context == context && oldKEKId.equals(metadata.kekId)) {
                    // Decrypt the DEK using the old KEK
                    Result<DEK, KMSError> decryptResult = effectiveKmsClient().decryptDEK(
                        metadata.encryptedDEK, oldKEKId
                    );
                    if (decryptResult.isFailure()) {
                        KMSError kmsError = decryptResult.getError().orElseThrow();
                        logger.error("Failed to decrypt DEK {} during KEK rotation for context {}: {}",
                            metadata.keyId, context, kmsError.getMessage());
                        return Result.failure(KeyError.of(
                            "KMS_DECRYPTION_FAILED",
                            "Failed to decrypt DEK " + metadata.keyId + " during KEK rotation: " + kmsError.getMessage(),
                            new RuntimeException(kmsError.getMessage())
                        ));
                    }
                    
                    DEK dek = decryptResult.getValue().orElseThrow();
                    
                    // Re-encrypt the DEK with the new KEK
                    Result<EncryptedDEK, KMSError> reEncryptResult = effectiveKmsClient().encryptDEK(dek, newKEKId);
                    if (reEncryptResult.isFailure()) {
                        KMSError kmsError = reEncryptResult.getError().orElseThrow();
                        logger.error("Failed to re-encrypt DEK {} with new KEK during KEK rotation for context {}: {}",
                            metadata.keyId, context, kmsError.getMessage());
                        return Result.failure(KeyError.of(
                            "KMS_ENCRYPTION_FAILED",
                            "Failed to re-encrypt DEK " + metadata.keyId + " with new KEK: " + kmsError.getMessage(),
                            new RuntimeException(kmsError.getMessage())
                        ));
                    }
                    
                    // Update DEK metadata with new KEK ID and re-encrypted DEK
                    metadata.kekId = newKEKId;
                    metadata.encryptedDEK = reEncryptResult.getValue().orElseThrow();
                }
            }
            
            // Mark old KEK as rotated
            KEKMetadata oldKEKMetadata = kekMetadataStore.get(oldKEKId);
            if (oldKEKMetadata != null) {
                oldKEKMetadata.status = KeyStatus.ROTATED;
                oldKEKMetadata.rotatedAt = Instant.now();
            }
        }
        
        // Store new KEK metadata
        kekMetadataStore.put(newKEKId, new KEKMetadata(
            newKEKId, context, environment, Instant.now(), null, KeyStatus.ACTIVE
        ));
        
        // Update active KEK ID for this context
        kekIds.put(context, newKEKId);
        
        // Invalidate all cached DEKs for this context so they are re-fetched with new KEK
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
     * Returns the effective KMS client: the circuit breaker when configured,
     * otherwise the raw kmsClient.
     */
    private IKMSClient effectiveKmsClient() {
        return circuitBreaker != null ? circuitBreaker : kmsClient;
    }

    /**
     * Checks KMS availability via health check and manages the unavailability
     * tracking / alerting lifecycle.
     *
     * <p>If the health check fails and a circuit breaker is configured, a
     * CRITICAL security event is logged. After 2 minutes of continuous
     * unavailability an additional CRITICAL alert is emitted.
     */
    private void checkKmsAvailability() {
        Result<KMSHealth, KMSError> healthResult = effectiveKmsClient().healthCheck();

        boolean available = healthResult.isSuccess() &&
                healthResult.getValue().map(KMSHealth::isAvailable).orElse(false);

        if (!available) {
            long now = System.currentTimeMillis();
            long since = kmsUnavailableSince.compareAndExchange(0L, now);
            if (since == 0L) {
                since = now; // first time we recorded unavailability
            }

            if (circuitBreaker != null) {
                String msg = healthResult.isFailure()
                        ? healthResult.getError().map(KMSError::getMessage).orElse("unknown")
                        : healthResult.getValue().map(KMSHealth::getMessage).orElse("unhealthy");

                logSecurityEvent("KMS_UNAVAILABLE", null, "KMS health check failed: " + msg);
            }

            long unavailableMs = now - since;
            if (unavailableMs >= KMS_ALERT_THRESHOLD_MS) {
                logger.error("ALERT: KMS has been unavailable for {}ms (threshold {}ms) – operations team must be notified",
                        unavailableMs, KMS_ALERT_THRESHOLD_MS);
                if (circuitBreaker != null) {
                    logSecurityEvent("KMS_PROLONGED_UNAVAILABILITY", null,
                            "KMS unavailable for " + unavailableMs + "ms – alerting operations");
                }
            }
        } else {
            // KMS is back – reset the unavailability tracker
            kmsUnavailableSince.set(0L);
        }
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
        DEKMetadata metadata = keyId != null ? dekMetadataStore.get(keyId) : null;
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
    
    @Override
    public Result<byte[], KeyError> getBlindIndexKey() {
        // The blind index key is stored as a fixed-size 32-byte key in the metadata store.
        // In production this would be fetched from KMS; here we use a cached in-memory key.
        if (blindIndexKey == null) {
            return Result.failure(KeyError.of(
                "BLIND_INDEX_KEY_NOT_INITIALIZED",
                "Blind index key has not been initialized. Call initializeBlindIndexKey() first."
            ));
        }
        return Result.success(Arrays.copyOf(blindIndexKey, blindIndexKey.length));
    }

    /**
     * Initializes a KEK for a bounded context.
     * This should be called during system setup.
     */
    public Result<UUID, KeyError> initializeKEK(BoundedContext context) {
        Result<UUID, KMSError> generateResult = effectiveKmsClient().generateKEK(context, environment);
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
        
        // Store KEK metadata
        kekMetadataStore.put(kekId, new KEKMetadata(
            kekId, context, environment, Instant.now(), null, KeyStatus.ACTIVE
        ));
        
        logger.info("KEK initialized for context: {}, KEK ID: {}", context, kekId);
        
        return Result.success(kekId);
    }

    /**
     * Initializes the blind index key with a cryptographically secure random 256-bit key.
     * In production, this key would be stored in and retrieved from KMS.
     */
    public void initializeBlindIndexKey() {
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);
        this.blindIndexKey = key;
        logger.info("Blind index key initialized");
    }

    /**
     * Sets the blind index key directly (for testing or when loading from KMS).
     */
    public void setBlindIndexKey(byte[] key) {
        Objects.requireNonNull(key, "Blind index key cannot be null");
        if (key.length != 32) {
            throw new IllegalArgumentException("Blind index key must be exactly 256 bits (32 bytes)");
        }
        this.blindIndexKey = Arrays.copyOf(key, key.length);
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

    /**
     * Internal class to store KEK metadata.
     */
    private static class KEKMetadata {
        UUID keyId;
        BoundedContext context;
        Environment environment;
        Instant createdAt;
        Instant rotatedAt;
        KeyStatus status;

        KEKMetadata(UUID keyId, BoundedContext context, Environment environment,
                    Instant createdAt, Instant rotatedAt, KeyStatus status) {
            this.keyId = keyId;
            this.context = context;
            this.environment = environment;
            this.createdAt = createdAt;
            this.rotatedAt = rotatedAt;
            this.status = status;
        }
    }
}
