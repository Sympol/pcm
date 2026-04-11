package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of IEncryptionService using AES-256-GCM encryption.
 * 
 * <p>This service provides:
 * <ul>
 *   <li>AES-256-GCM authenticated encryption for PII data</li>
 *   <li>Counter-based IV generation with automatic DEK rotation on overflow</li>
 *   <li>Ciphertext formatting with version, algorithm, key ID, IV, and auth tag</li>
 *   <li>Batch encryption/decryption operations for performance</li>
 *   <li>Comprehensive audit logging of all operations</li>
 *   <li>Graceful error handling with Result types</li>
 * </ul>
 * 
 */
public class EncryptionService implements IEncryptionService {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128; // 16 bytes
    private static final String SERVICE_IDENTITY = "EncryptionService";
    
    private final IKeyManager keyManager;
    private final BlindIndexService blindIndexService;
    private final IAuditLogger auditLogger;
    private final IVCounter ivCounter;

    public EncryptionService(
            IKeyManager keyManager,
            BlindIndexService blindIndexService,
            IAuditLogger auditLogger,
            IVCounter ivCounter) {
        this.keyManager = Objects.requireNonNull(keyManager, "KeyManager cannot be null");
        this.blindIndexService = Objects.requireNonNull(blindIndexService, "BlindIndexService cannot be null");
        this.auditLogger = Objects.requireNonNull(auditLogger, "AuditLogger cannot be null");
        this.ivCounter = Objects.requireNonNull(ivCounter, "IVCounter cannot be null");

        // Log the JCE provider being used for AES/GCM — AES-NI is used automatically
        // by SunJCE on x86/x64 hardware that supports it.
        try {
            Cipher probe = Cipher.getInstance(CIPHER_TRANSFORMATION);
            logger.info("AES/GCM cipher provider: {} (AES-NI used automatically when available)",
                        probe.getProvider().getName());
        } catch (Exception e) {
            logger.warn("Could not probe AES/GCM cipher provider", e);
        }
    }

    @Override
    public Result<Ciphertext, EncryptionError> encrypt(String plaintext, BoundedContext context) {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        Objects.requireNonNull(context, "Context cannot be null");

        UUID keyId = null;

        try {
            // 1. Get active DEK from KeyManager
            Result<DEKWithMetadata, KeyError> dekResult = keyManager.getActiveDEK(context);
            if (dekResult.isFailure()) {
                KeyError keyError = dekResult.getError().orElseThrow();
                EncryptionError error = EncryptionError.of(
                    EncryptionErrorCodes.KEY_UNAVAILABLE,
                    "Encryption key is unavailable for context: " + context.name(),
                    keyError.getCause()
                );
                logEncryptionFailure(context, null, error);
                return Result.failure(error);
            }

            DEKWithMetadata dekMetadata = dekResult.getValue().orElseThrow();
            keyId = dekMetadata.getKeyId();
            DEK dek = dekMetadata.getDek();

            // 2. Generate IV using counter-based approach
            Result<IV, IVCounterError> ivResult = ivCounter.generateIV(keyId);
            if (ivResult.isFailure()) {
                IVCounterError ivError = ivResult.getError().orElseThrow();
                EncryptionErrorCodes code = isCounterOverflow(ivError)
                    ? EncryptionErrorCodes.COUNTER_OVERFLOW
                    : EncryptionErrorCodes.IV_GENERATION_FAILED;
                EncryptionError error = EncryptionError.of(code);
                logEncryptionFailure(context, keyId, error);
                return Result.failure(error);
            }

            IV iv = ivResult.getValue().orElseThrow();

            // 3. Prepare Additional Authenticated Data (AAD)
            byte[] aad = generateAAD(context, keyId);

            // 4. Perform AES-256-GCM encryption
            Result<EncryptedData, EncryptionError> encryptResult = performEncryption(
                plaintext,
                dek,
                iv,
                aad
            );

            if (encryptResult.isFailure()) {
                EncryptionError error = encryptResult.getError().orElseThrow();
                logEncryptionFailure(context, keyId, error);
                return Result.failure(error);
            }

            EncryptedData encryptedData = encryptResult.getValue().orElseThrow();

            // 5. Format ciphertext
            Result<Ciphertext, DecryptionError> formatResult = CiphertextFormat.format(
                CiphertextFormat.VERSION_1,
                CiphertextFormat.ALGORITHM_AES_256_GCM,
                keyId,
                iv.getValue(),
                encryptedData.ciphertext,
                encryptedData.authTag
            );

            if (formatResult.isFailure()) {
                EncryptionError error = EncryptionError.of(EncryptionErrorCodes.ENCRYPTION_FAILED);
                logEncryptionFailure(context, keyId, error);
                return Result.failure(error);
            }

            Ciphertext ciphertext = formatResult.getValue().orElseThrow();

            // 6. Log successful operation
            logEncryptionSuccess(context, keyId);

            return Result.success(ciphertext);

        } catch (Exception e) {
            EncryptionError error = EncryptionError.of(
                EncryptionErrorCodes.ENCRYPTION_FAILED,
                EncryptionErrorCodes.ENCRYPTION_FAILED.getDefaultMessage(),
                e
            );
            logEncryptionFailure(context, keyId, error);
            return Result.failure(error);
        }
    }

    @Override
    public Result<String, DecryptionError> decrypt(Ciphertext ciphertext, BoundedContext context) {
        Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
        Objects.requireNonNull(context, "Context cannot be null");

        UUID keyId = null;

        try {
            // 1. Parse ciphertext format
            Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult = 
                CiphertextFormat.parse(ciphertext);

            if (parseResult.isFailure()) {
                DecryptionError error = parseResult.getError().orElseThrow();
                logDecryptionFailure(context, null, error);
                return Result.failure(error);
            }

            CiphertextFormat.ParsedCiphertext parsed = parseResult.getValue().orElseThrow();
            keyId = parsed.getKeyId();

            // 2. Validate version and algorithm
            if (parsed.getVersion() != CiphertextFormat.VERSION_1) {
                DecryptionError error = DecryptionError.of(EncryptionErrorCodes.UNSUPPORTED_VERSION);
                logDecryptionFailure(context, keyId, error);
                return Result.failure(error);
            }

            if (parsed.getAlgorithm() != EncryptionAlgorithm.AES_256_GCM) {
                DecryptionError error = DecryptionError.of(EncryptionErrorCodes.UNSUPPORTED_ALGORITHM);
                logDecryptionFailure(context, keyId, error);
                return Result.failure(error);
            }

            // 3. Get DEK by key ID from KeyManager
            Result<DEKWithMetadata, KeyError> dekResult = keyManager.getDEK(keyId);
            if (dekResult.isFailure()) {
                KeyError keyError = dekResult.getError().orElseThrow();
                DecryptionError error = DecryptionError.of(
                    EncryptionErrorCodes.KEY_NOT_FOUND,
                    EncryptionErrorCodes.KEY_NOT_FOUND.getDefaultMessage(),
                    keyError.getCause()
                );
                logDecryptionFailure(context, keyId, error);
                return Result.failure(error);
            }

            DEKWithMetadata dekMetadata = dekResult.getValue().orElseThrow();
            DEK dek = dekMetadata.getDek();

            // 4. Prepare Additional Authenticated Data (AAD)
            byte[] aad = generateAAD(context, keyId);

            // 5. Perform AES-256-GCM decryption with authentication tag verification
            Result<String, DecryptionError> decryptResult = performDecryption(
                parsed.getCiphertext(),
                parsed.getAuthTag(),
                dek,
                IV.of(parsed.getIv()),
                aad,
                context,
                keyId
            );

            if (decryptResult.isFailure()) {
                DecryptionError error = decryptResult.getError().orElseThrow();
                logDecryptionFailure(context, keyId, error);
                return Result.failure(error);
            }

            String plaintext = decryptResult.getValue().orElseThrow();

            // 6. Log successful operation
            logDecryptionSuccess(context, keyId);

            return Result.success(plaintext);

        } catch (Exception e) {
            DecryptionError error = DecryptionError.of(
                EncryptionErrorCodes.DECRYPTION_FAILED,
                EncryptionErrorCodes.DECRYPTION_FAILED.getDefaultMessage(),
                e
            );
            logDecryptionFailure(context, keyId, error);
            return Result.failure(error);
        }
    }

    @Override
    public Result<List<Ciphertext>, EncryptionError> encryptBatch(
            List<String> plaintexts,
            BoundedContext context) {
        
        Objects.requireNonNull(plaintexts, "Plaintexts list cannot be null");
        Objects.requireNonNull(context, "Context cannot be null");

        if (plaintexts.isEmpty()) {
            return Result.success(List.of());
        }

        try {
            // Get active DEK once for the entire batch (optimization)
            Result<DEKWithMetadata, KeyError> dekResult = keyManager.getActiveDEK(context);
            if (dekResult.isFailure()) {
                KeyError keyError = dekResult.getError().orElseThrow();
                EncryptionError error = EncryptionError.of(
                    EncryptionErrorCodes.KEY_UNAVAILABLE,
                    "Encryption key is unavailable for context: " + context.name(),
                    keyError.getCause()
                );
                return Result.failure(error);
            }

            DEKWithMetadata dekMetadata = dekResult.getValue().orElseThrow();
            UUID keyId = dekMetadata.getKeyId();
            DEK dek = dekMetadata.getDek();
            byte[] aad = generateAAD(context, keyId);

            List<Ciphertext> ciphertexts = new ArrayList<>(plaintexts.size());

            // Encrypt each plaintext with the same DEK but unique IVs
            for (String plaintext : plaintexts) {
                if (plaintext == null) {
                    return Result.failure(EncryptionError.of(EncryptionErrorCodes.INVALID_PLAINTEXT));
                }

                // Generate unique IV for this item
                Result<IV, IVCounterError> ivResult = ivCounter.generateIV(keyId);
                if (ivResult.isFailure()) {
                    IVCounterError ivError = ivResult.getError().orElseThrow();
                    EncryptionErrorCodes code = isCounterOverflow(ivError)
                        ? EncryptionErrorCodes.COUNTER_OVERFLOW
                        : EncryptionErrorCodes.IV_GENERATION_FAILED;
                    return Result.failure(EncryptionError.of(code));
                }

                IV iv = ivResult.getValue().orElseThrow();

                // Perform encryption
                Result<EncryptedData, EncryptionError> encryptResult = performEncryption(
                    plaintext,
                    dek,
                    iv,
                    aad
                );

                if (encryptResult.isFailure()) {
                    return Result.failure(encryptResult.getError().orElseThrow());
                }

                EncryptedData encryptedData = encryptResult.getValue().orElseThrow();

                // Format ciphertext
                Result<Ciphertext, DecryptionError> formatResult = CiphertextFormat.format(
                    CiphertextFormat.VERSION_1,
                    CiphertextFormat.ALGORITHM_AES_256_GCM,
                    keyId,
                    iv.getValue(),
                    encryptedData.ciphertext,
                    encryptedData.authTag
                );

                if (formatResult.isFailure()) {
                    return Result.failure(EncryptionError.of(EncryptionErrorCodes.ENCRYPTION_FAILED));
                }

                ciphertexts.add(formatResult.getValue().orElseThrow());
            }

            // Log batch operation
            logEncryptionSuccess(context, keyId, plaintexts.size());

            return Result.success(ciphertexts);

        } catch (Exception e) {
            // Do not expose e.getMessage() – it may contain sensitive data (req 8.6)
            return Result.failure(EncryptionError.of(
                EncryptionErrorCodes.ENCRYPTION_FAILED,
                EncryptionErrorCodes.ENCRYPTION_FAILED.getDefaultMessage()
            ));
        }
    }

    @Override
    public Result<List<String>, DecryptionError> decryptBatch(
            List<Ciphertext> ciphertexts,
            BoundedContext context) {
        
        Objects.requireNonNull(ciphertexts, "Ciphertexts list cannot be null");
        Objects.requireNonNull(context, "Context cannot be null");

        if (ciphertexts.isEmpty()) {
            return Result.success(List.of());
        }

        try {
            // 1. Parse all ciphertexts first to extract key IDs
            List<CiphertextFormat.ParsedCiphertext> parsed = new ArrayList<>(ciphertexts.size());
            for (Ciphertext ct : ciphertexts) {
                if (ct == null) {
                    return Result.failure(DecryptionError.of(
                        "INVALID_CIPHERTEXT",
                        "Ciphertext in batch cannot be null"
                    ));
                }
                Result<CiphertextFormat.ParsedCiphertext, DecryptionError> parseResult =
                    CiphertextFormat.parse(ct);
                if (parseResult.isFailure()) {
                    return Result.failure(parseResult.getError().orElseThrow());
                }
                CiphertextFormat.ParsedCiphertext p = parseResult.getValue().orElseThrow();
                // Validate version and algorithm eagerly
                if (p.getVersion() != CiphertextFormat.VERSION_1) {
                    return Result.failure(DecryptionError.of(EncryptionErrorCodes.UNSUPPORTED_VERSION));
                }
                if (p.getAlgorithm() != EncryptionAlgorithm.AES_256_GCM) {
                    return Result.failure(DecryptionError.of(EncryptionErrorCodes.UNSUPPORTED_ALGORITHM));
                }
                parsed.add(p);
            }

            // 2. Pre-fetch unique DEKs — O(k) KMS calls where k = number of unique key IDs
            Map<UUID, DEKWithMetadata> dekMap = new LinkedHashMap<>();
            for (CiphertextFormat.ParsedCiphertext p : parsed) {
                UUID keyId = p.getKeyId();
                if (!dekMap.containsKey(keyId)) {
                    Result<DEKWithMetadata, KeyError> dekResult = keyManager.getDEK(keyId);
                    if (dekResult.isFailure()) {
                        KeyError keyError = dekResult.getError().orElseThrow();
                        return Result.failure(DecryptionError.of(
                            EncryptionErrorCodes.KEY_NOT_FOUND,
                            EncryptionErrorCodes.KEY_NOT_FOUND.getDefaultMessage(),
                            keyError.getCause()
                        ));
                    }
                    dekMap.put(keyId, dekResult.getValue().orElseThrow());
                }
            }

            // 3. Decrypt each ciphertext using pre-fetched DEKs (no additional KMS calls)
            List<String> plaintexts = new ArrayList<>(ciphertexts.size());
            for (CiphertextFormat.ParsedCiphertext p : parsed) {
                DEKWithMetadata dekMetadata = dekMap.get(p.getKeyId());
                DEK dek = dekMetadata.getDek();
                byte[] aad = generateAAD(context, p.getKeyId());

                Result<String, DecryptionError> decryptResult = performDecryption(
                    p.getCiphertext(),
                    p.getAuthTag(),
                    dek,
                    IV.of(p.getIv()),
                    aad,
                    context,
                    p.getKeyId()
                );

                if (decryptResult.isFailure()) {
                    return Result.failure(decryptResult.getError().orElseThrow());
                }

                plaintexts.add(decryptResult.getValue().orElseThrow());
            }

            // 4. Log a single batch decryption event
            logDecryptionSuccess(context, null, ciphertexts.size());

            return Result.success(plaintexts);

        } catch (Exception e) {
            // Do not expose e.getMessage() – it may contain sensitive data (req 8.6)
            return Result.failure(DecryptionError.of(
                EncryptionErrorCodes.DECRYPTION_FAILED,
                EncryptionErrorCodes.DECRYPTION_FAILED.getDefaultMessage()
            ));
        }
    }

    @Override
    public Result<BlindIndex, EncryptionError> generateBlindIndex(String plaintext, String recordSalt) {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        Objects.requireNonNull(recordSalt, "Record salt cannot be null");
        return blindIndexService.generateBlindIndex(plaintext, recordSalt);
    }

    @Override
    public Result<Ciphertext, EncryptionError> shareAcrossContexts(
            Ciphertext ciphertext,
            BoundedContext sourceContext,
            BoundedContext targetContext) {

        Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
        Objects.requireNonNull(sourceContext, "Source context cannot be null");
        Objects.requireNonNull(targetContext, "Target context cannot be null");

        // 1. Decrypt with source context DEK
        Result<String, DecryptionError> decryptResult = decrypt(ciphertext, sourceContext);
        if (decryptResult.isFailure()) {
            DecryptionError decryptionError = decryptResult.getError().orElseThrow();
            return Result.failure(EncryptionError.of(
                EncryptionErrorCodes.ENCRYPTION_FAILED,
                "Cross-context data sharing failed during decryption from context: " + sourceContext.name(),
                decryptionError.getCause()
            ));
        }

        String plaintext = decryptResult.getValue().orElseThrow();

        // 2. Re-encrypt with target context DEK
        Result<Ciphertext, EncryptionError> encryptResult = encrypt(plaintext, targetContext);
        if (encryptResult.isFailure()) {
            return Result.failure(EncryptionError.of(
                EncryptionErrorCodes.ENCRYPTION_FAILED,
                "Cross-context data sharing failed during re-encryption to context: " + targetContext.name(),
                encryptResult.getError().orElseThrow().getCause()
            ));
        }

        return encryptResult;
    }

    /**
     * Performs AES-256-GCM encryption on plaintext.
     */
    private Result<EncryptedData, EncryptionError> performEncryption(
            String plaintext,
            DEK dek,
            IV iv,
            byte[] aad) {
        
        try {
            // Create cipher instance
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            
            // Create secret key from DEK
            SecretKey secretKey = new SecretKeySpec(dek.getKeyMaterial(), "AES");
            
            // Create GCM parameter spec with IV and tag length
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv.getValue());
            
            // Initialize cipher for encryption
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            
            // Set Additional Authenticated Data
            cipher.updateAAD(aad);
            
            // Perform encryption (includes auth tag generation)
            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertextWithTag = cipher.doFinal(plaintextBytes);
            
            // Split ciphertext and auth tag
            // GCM appends the tag to the ciphertext
            int ciphertextLength = ciphertextWithTag.length - (GCM_TAG_LENGTH_BITS / 8);
            byte[] ciphertext = new byte[ciphertextLength];
            byte[] authTag = new byte[GCM_TAG_LENGTH_BITS / 8];
            
            System.arraycopy(ciphertextWithTag, 0, ciphertext, 0, ciphertextLength);
            System.arraycopy(ciphertextWithTag, ciphertextLength, authTag, 0, authTag.length);
            
            return Result.success(new EncryptedData(ciphertext, authTag));
            
        } catch (Exception e) {
            // Do not expose e.getMessage() – it may contain sensitive data
            return Result.failure(EncryptionError.of(
                EncryptionErrorCodes.ENCRYPTION_FAILED,
                EncryptionErrorCodes.ENCRYPTION_FAILED.getDefaultMessage()
            ));
        }
    }

    /**
     * Performs AES-256-GCM decryption with authentication tag verification.
     */
    private Result<String, DecryptionError> performDecryption(
            byte[] ciphertext,
            byte[] authTag,
            DEK dek,
            IV iv,
            byte[] aad,
            BoundedContext context,
            UUID keyId) {
        
        try {
            // Create cipher instance
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            
            // Create secret key from DEK
            SecretKey secretKey = new SecretKeySpec(dek.getKeyMaterial(), "AES");
            
            // Create GCM parameter spec with IV and tag length
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv.getValue());
            
            // Initialize cipher for decryption
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            
            // Set Additional Authenticated Data
            cipher.updateAAD(aad);
            
            // Combine ciphertext and auth tag for decryption
            byte[] ciphertextWithTag = new byte[ciphertext.length + authTag.length];
            System.arraycopy(ciphertext, 0, ciphertextWithTag, 0, ciphertext.length);
            System.arraycopy(authTag, 0, ciphertextWithTag, ciphertext.length, authTag.length);
            
            // Perform decryption (includes auth tag verification)
            byte[] plaintextBytes = cipher.doFinal(ciphertextWithTag);
            
            String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
            return Result.success(plaintext);
            
        } catch (javax.crypto.AEADBadTagException e) {
            // Authentication tag verification failed – data has been tampered with 
            logTamperingDetected(context, keyId);
            return Result.failure(DecryptionError.of(EncryptionErrorCodes.TAMPERING_DETECTED));
        } catch (javax.crypto.BadPaddingException e) {
            // In GCM mode BadPaddingException also signals authentication failure 
            logTamperingDetected(context, keyId);
            return Result.failure(DecryptionError.of(EncryptionErrorCodes.TAMPERING_DETECTED));
        } catch (Exception e) {
            // Generic failure – do not expose e.getMessage() to callers 
            return Result.failure(DecryptionError.of(
                EncryptionErrorCodes.DECRYPTION_FAILED,
                EncryptionErrorCodes.DECRYPTION_FAILED.getDefaultMessage()
            ));
        }
    }

    /**
     * Determines whether an IVCounterError represents a counter overflow condition.
     */
    private boolean isCounterOverflow(IVCounterError error) {
        return error != null && "IV_COUNTER_OVERFLOW".equals(error.getCode());
    }

    /**
     * Generates Additional Authenticated Data (AAD) from context and key ID.
     * AAD prevents substitution attacks by binding the ciphertext to its context.
     */
    private byte[] generateAAD(BoundedContext context, UUID keyId) {
        String aadString = context.name() + "|" + keyId.toString();
        return aadString.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Logs successful encryption operation.
     */
    private void logEncryptionSuccess(BoundedContext context, UUID keyId) {
        logEncryptionSuccess(context, keyId, 1);
    }

    /**
     * Logs successful encryption operation with count.
     */
    private void logEncryptionSuccess(BoundedContext context, UUID keyId, int count) {
        EncryptionEvent event = EncryptionEvent.builder()
            .timestamp(Instant.now())
            .context(context)
            .serviceIdentity(SERVICE_IDENTITY)
            .keyId(keyId)
            .success(true)
            .metadata(count > 1 ? java.util.Map.of("batchSize", count) : java.util.Map.of())
            .build();
        
        auditLogger.logEncryption(event);
    }

    /**
     * Logs failed encryption operation.
     */
    private void logEncryptionFailure(BoundedContext context, UUID keyId, EncryptionError error) {
        EncryptionEvent event = EncryptionEvent.builder()
            .timestamp(Instant.now())
            .context(context)
            .serviceIdentity(SERVICE_IDENTITY)
            .keyId(keyId)
            .success(false)
            .errorCode(error.getCode())
            .build();
        
        auditLogger.logEncryption(event);
    }

    /**
     * Logs successful decryption operation.
     */
    private void logDecryptionSuccess(BoundedContext context, UUID keyId) {
        logDecryptionSuccess(context, keyId, 1);
    }

    /**
     * Logs successful decryption operation with count (used for batch operations).
     */
    private void logDecryptionSuccess(BoundedContext context, UUID keyId, int count) {
        DecryptionEvent event = DecryptionEvent.builder()
            .timestamp(Instant.now())
            .context(context)
            .serviceIdentity(SERVICE_IDENTITY)
            .keyId(keyId)
            .success(true)
            .metadata(count > 1 ? java.util.Map.of("batchSize", count) : java.util.Map.of())
            .build();
        
        auditLogger.logDecryption(event);
    }

    /**
     * Logs failed decryption operation.
     */
    private void logDecryptionFailure(BoundedContext context, UUID keyId, DecryptionError error) {
        DecryptionEvent event = DecryptionEvent.builder()
            .timestamp(Instant.now())
            .context(context)
            .serviceIdentity(SERVICE_IDENTITY)
            .keyId(keyId)
            .success(false)
            .errorCode(error.getCode())
            .build();
        
        auditLogger.logDecryption(event);
    }

    /**
     * Logs tampering detection as a security event.
     */
    private void logTamperingDetected(BoundedContext context, UUID keyId) {
        SecurityEvent event = SecurityEvent.builder()
            .timestamp(Instant.now())
            .context(context)
            .serviceIdentity(SERVICE_IDENTITY)
            .eventType("TAMPERING_DETECTED")
            .severity("CRITICAL")
            .keyId(keyId)
            .description("Authentication tag verification failed during decryption")
            .build();
        
        auditLogger.logSecurityEvent(event);
    }

    /**
     * Internal class to hold encrypted data and authentication tag.
     */
    private static class EncryptedData {
        final byte[] ciphertext;
        final byte[] authTag;

        EncryptedData(byte[] ciphertext, byte[] authTag) {
            this.ciphertext = ciphertext;
            this.authTag = authTag;
        }
    }
}
