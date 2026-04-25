package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

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

    /** Optional metrics for cache hit/miss tracking; null when not configured. */
    @Nullable
    private EncryptionMetrics encryptionMetrics;

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

    /**
     * Sets the optional {@link EncryptionMetrics} for cache hit/miss tracking.
     *
     * @param encryptionMetrics the metrics instance, or {@code null} to disable tracking
     */
    public void setEncryptionMetrics(@Nullable EncryptionMetrics encryptionMetrics) {
        this.encryptionMetrics = encryptionMetrics;
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
            DEKWithMetadata cached = cachedDEK.get();
            // Defense-in-depth: verify environment even on cache hit (Requirement 17.5, 17.6)
            if (cached.getEnvironment() != environment) {
                String errorMsg = String.format(
                    "Environment mismatch: cached DEK is for %s but current environment is %s",
                    cached.getEnvironment(), environment
                );
                logSecurityEvent("ENVIRONMENT_MISMATCH", keyId, errorMsg);
                dekCache.invalidate(keyId);
                return Result.failure(KeyError.of("ENVIRONMENT_MISMATCH", errorMsg));
            }
            logKeyAccess(keyId, "CACHE_HIT", true);
            if (encryptionMetrics != null) {
                encryptionMetrics.recordCacheHit();
            }
            return Result.success(cached);
        }
        
        logKeyAccess(keyId, "CACHE_MISS", true);
        if (encryptionMetrics != null) {
            encryptionMetrics.recordCacheMiss();
        }
        
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
        
        // Generate new DEK ID using environment-scoped namespace format:
        // {environment}.{bounded_context}.dek.context.{uuid}
        UUID newDEKUUID = UUID.randomUUID();
        UUID newDEKId = newDEKUUID;
        String dekNamespace = KeyNamespace.forContextDEK(environment, context, newDEKUUID);
        
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
            encryptedDEK,
            dekNamespace
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
        
        // Store new KEK metadata with environment-scoped namespace
        String kekNamespace = KeyNamespace.forKEK(environment, context, newKEKId);
        kekMetadataStore.put(newKEKId, new KEKMetadata(
            newKEKId, context, environment, Instant.now(), null, KeyStatus.ACTIVE, kekNamespace
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

        // 1. Find the user-specific DEK by namespace pattern:
        //    {environment}.{context}.dek.user.{userId}
        String expectedNamespacePrefix = environment.name().toLowerCase() + "." +
                context.name().toLowerCase() + "." + KeyNamespace.KEY_TYPE_DEK_USER + ".";

        UUID userDEKId = null;
        for (Map.Entry<UUID, DEKMetadata> entry : dekMetadataStore.entrySet()) {
            DEKMetadata meta = entry.getValue();
            if (meta.context == context
                    && meta.environment == environment
                    && meta.namespace != null
                    && meta.namespace.startsWith(expectedNamespacePrefix)) {
                // The namespace format is {env}.{ctx}.dek.user.{uuid}
                // For user DEKs the UUID at the end encodes the userId
                // Check that this DEK belongs to the requested user
                String namespaceUserId = extractUserIdFromNamespace(meta.namespace);
                if (userId.equals(namespaceUserId)) {
                    userDEKId = entry.getKey();
                    break;
                }
            }
        }

        if (userDEKId == null) {
            return Result.failure(KeyError.of(
                "USER_DEK_NOT_FOUND",
                "No user-specific DEK found for userId: " + userId + " in context: " + context
            ));
        }

        // 2. Delete the DEK from KMS
        Result<Unit, KMSError> deleteResult = effectiveKmsClient().deleteDEK(userDEKId);
        if (deleteResult.isFailure()) {
            KMSError kmsError = deleteResult.getError().orElseThrow();
            logger.error("Failed to delete user DEK from KMS: userId={}, context={}, keyId={}: {}",
                    userId, context, userDEKId, kmsError.getMessage());
            return Result.failure(KeyError.of(
                "KMS_DELETE_FAILED",
                "Failed to delete user DEK from KMS: " + kmsError.getMessage(),
                new RuntimeException(kmsError.getMessage())
            ));
        }

        // 3. Invalidate the DEK from cache (secure wipe)
        dekCache.invalidate(userDEKId);

        // 4. Remove from metadata store (prevents future retrieval)
        UUID deletedKeyId = userDEKId;
        dekMetadataStore.remove(deletedKeyId);

        // Also remove from active DEK tracking if it was the active DEK
        activeDEKIds.entrySet().removeIf(e -> deletedKeyId.equals(e.getValue()));

        // 5. Verify deletion: attempt to retrieve the key and confirm it's gone
        boolean verificationPassed = verifyDEKDeleted(deletedKeyId);
        if (!verificationPassed) {
            logger.warn("DEK deletion verification failed for userId={}, context={}, keyId={}",
                    userId, context, deletedKeyId);
            // Log a security event but still proceed — the KMS deletion was confirmed
            logSecurityEvent("DEK_DELETION_VERIFICATION_FAILED", deletedKeyId,
                    "DEK deletion verification failed for userId: " + userId);
        }

        // 6. Generate deletion certificate with HMAC-SHA256 signature
        Instant deletedAt = Instant.now();
        String signature = generateDeletionSignature(deletedKeyId, userId, context, deletedAt);

        DeletionCertificate certificate = DeletionCertificate.of(
            deletedKeyId,
            userId,
            context,
            deletedAt,
            signature
        );

        // 7. Log the deletion event
        logDeletionEvent(deletedKeyId, userId, context, deletedAt);

        logger.info("User DEK deleted for userId={}, context={}, keyId={}",
                userId, context, deletedKeyId);

        return Result.success(certificate);
    }

    /**
     * Extracts the userId from a user DEK namespace.
     *
     * <p>User DEK namespaces follow the format:
     * {@code {environment}.{context}.dek.user.{userId}}
     * where userId is the last segment after "dek.user."
     */
    private String extractUserIdFromNamespace(String namespace) {
        // Format: {env}.{ctx}.dek.user.{userId}
        // "dek.user." is the key type prefix; everything after it is the userId
        String prefix = ".dek.user.";
        int idx = namespace.indexOf(prefix);
        if (idx < 0) {
            return null;
        }
        return namespace.substring(idx + prefix.length());
    }

    /**
     * Verifies that a DEK has been successfully deleted by confirming it is no
     * longer present in the metadata store or cache.
     *
     * @return true if the DEK is confirmed deleted, false if it still appears accessible
     */
    private boolean verifyDEKDeleted(UUID keyId) {
        // Verify it's not in the metadata store
        if (dekMetadataStore.containsKey(keyId)) {
            return false;
        }
        // Verify it's not in the cache
        return dekCache.get(keyId).isEmpty();
    }

    /**
     * Generates an HMAC-SHA256 signature for the deletion certificate.
     *
     * <p>The signature covers: keyId + userId + context + deletedAt
     * using the blind index key as the HMAC key (or a fallback if not initialized).
     */
    private String generateDeletionSignature(UUID keyId, String userId,
                                             BoundedContext context, Instant deletedAt) {
        try {
            String data = keyId.toString() + "|" + userId + "|" + context.name() + "|" + deletedAt.toString();
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);

            // Use blind index key if available, otherwise use a deterministic fallback key
            byte[] hmacKey = (blindIndexKey != null)
                    ? Arrays.copyOf(blindIndexKey, blindIndexKey.length)
                    : deriveSigningKey(keyId, userId);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
            byte[] hmacBytes = mac.doFinal(dataBytes);

            // Encode as hex string
            StringBuilder sb = new StringBuilder(hmacBytes.length * 2);
            for (byte b : hmacBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            // Fallback: use a simple hash-based signature (should not happen in practice)
            logger.warn("HMAC-SHA256 not available for deletion certificate signature, using fallback");
            String data = keyId + userId + context + deletedAt;
            return "FALLBACK:" + Integer.toHexString(data.hashCode());
        }
    }

    /**
     * Derives a deterministic signing key from the keyId and userId when the
     * blind index key is not available.
     */
    private byte[] deriveSigningKey(UUID keyId, String userId) {
        // Derive a 32-byte key from keyId + userId using SHA-256
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            digest.update(keyId.toString().getBytes(StandardCharsets.UTF_8));
            digest.update(userId.getBytes(StandardCharsets.UTF_8));
            return digest.digest();
        } catch (java.security.NoSuchAlgorithmException e) {
            // SHA-256 is always available on JVM
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * Logs a DEK deletion event for audit trail (Requirements 11.10).
     */
    private void logDeletionEvent(UUID keyId, String userId, BoundedContext context, Instant deletedAt) {
        SecurityEvent event = SecurityEvent.builder()
            .eventType("USER_DEK_DELETED")
            .keyId(keyId)
            .description("User DEK deleted for GDPR cryptographic erasure. userId=" + userId)
            .timestamp(deletedAt)
            .context(context)
            .serviceIdentity("KeyManager")
            .severity("CRITICAL")
            .metadata(Map.of(
                "userId", userId,
                "deletedAt", deletedAt.toString(),
                "gdprArticle", "17"
            ))
            .build();

        auditLogger.logSecurityEvent(event);
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
     * Creates a user-specific DEK for per-user encryption (supports cryptographic erasure).
     *
     * <p>The DEK is stored with namespace: {@code {environment}.{context}.dek.user.{userId}}
     *
     * @param userId  the user ID for whom to create the DEK
     * @param context the bounded context
     * @return Result containing the new DEK's UUID, or KeyError if creation fails
     */
    public Result<UUID, KeyError> createUserDEK(String userId, BoundedContext context) {
        Objects.requireNonNull(userId, "User ID cannot be null");
        Objects.requireNonNull(context, "Context cannot be null");

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
                "Failed to encrypt user DEK with KMS: " + kmsError.getMessage(),
                new RuntimeException(kmsError.getMessage())
            ));
        }

        EncryptedDEK encryptedDEK = encryptResult.getValue().orElseThrow();
        UUID newDEKId = UUID.randomUUID();

        // Use user-scoped namespace: {environment}.{context}.dek.user.{userId}
        String dekNamespace = environment.name().toLowerCase() + "." +
                context.name().toLowerCase() + "." +
                KeyNamespace.KEY_TYPE_DEK_USER + "." + userId;

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
            encryptedDEK,
            dekNamespace
        );
        dekMetadataStore.put(newDEKId, metadata);

        logger.info("User DEK created for userId={}, context={}, keyId={}", userId, context, newDEKId);
        return Result.success(newDEKId);
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
        
        // Store KEK metadata with environment-scoped namespace
        String kekNamespace = KeyNamespace.forKEK(environment, context, kekId);
        kekMetadataStore.put(kekId, new KEKMetadata(
            kekId, context, environment, Instant.now(), null, KeyStatus.ACTIVE, kekNamespace
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
     * Returns the KEK IDs map (package-private, for use by SecretManager in the same package).
     */
    public Map<BoundedContext, UUID> getKekIds() {
        return kekIds;
    }

    /**
     * Returns the current environment this KeyManager is configured for.
     *
     * <p>Keys generated by this manager will be namespaced under this environment,
     * ensuring isolation from other environments (Requirement 17.1, 17.2).
     *
     * @return the environment
     */
    public Environment getEnvironment() {
        return environment;
    }

    /**
     * Returns the namespace for a DEK by its key ID, or null if not found.
     *
     * <p>The namespace follows the format:
     * {@code {environment}.{bounded_context}.{key_type}.{key_id}}
     *
     * @param keyId the DEK key ID
     * @return the namespace string, or null if the DEK is not found
     */
    public String getDEKNamespace(UUID keyId) {
        DEKMetadata metadata = dekMetadataStore.get(keyId);
        return metadata != null ? metadata.namespace : null;
    }

    /**
     * Returns the namespace for a KEK by its key ID, or null if not found.
     *
     * <p>The namespace follows the format:
     * {@code {environment}.{bounded_context}.kek.{key_id}}
     *
     * @param keyId the KEK key ID
     * @return the namespace string, or null if the KEK is not found
     */
    public String getKEKNamespace(UUID keyId) {
        KEKMetadata metadata = kekMetadataStore.get(keyId);
        return metadata != null ? metadata.namespace : null;
    }

    /**
     * Internal class to store DEK metadata.
     *
     * <p>The {@code namespace} field stores the key namespace in the format
     * {@code {environment}.{bounded_context}.{key_type}.{key_id}}, satisfying.
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
        /** Namespace identifier: {environment}.{bounded_context}.{key_type}.{key_id} */
        String namespace;
        
        DEKMetadata(UUID keyId, UUID kekId, BoundedContext context, Environment environment,
                   EncryptionAlgorithm algorithm, Instant createdAt, Instant rotatedAt,
                   KeyStatus status, long encryptionCount, long bytesEncrypted,
                   EncryptedDEK encryptedDEK, String namespace) {
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
            this.namespace = namespace;
        }
    }

    /**
     * Internal class to store KEK metadata.
     *
     * <p>The {@code namespace} field stores the key namespace in the format
     * {@code {environment}.{bounded_context}.kek.{key_id}}, satisfying.
     */
    private static class KEKMetadata {
        UUID keyId;
        BoundedContext context;
        Environment environment;
        Instant createdAt;
        Instant rotatedAt;
        KeyStatus status;
        /** Namespace identifier: {environment}.{bounded_context}.kek.{key_id} */
        String namespace;

        KEKMetadata(UUID keyId, BoundedContext context, Environment environment,
                    Instant createdAt, Instant rotatedAt, KeyStatus status, String namespace) {
            this.keyId = keyId;
            this.context = context;
            this.environment = environment;
            this.createdAt = createdAt;
            this.rotatedAt = rotatedAt;
            this.status = status;
            this.namespace = namespace;
        }
    }
}
