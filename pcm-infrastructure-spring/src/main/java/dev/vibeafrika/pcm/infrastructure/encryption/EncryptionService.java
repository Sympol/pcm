package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

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
    }

    @Override
    public Result<Ciphertext, EncryptionError> encrypt(String plaintext, BoundedContext context) {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        Objects.requireNonNull(context, "Context cannot be null");

        Instant startTime = Instant.now();
        UUID keyId = null;

        try {
            // 1. Get active DEK from KeyManager
            Result<DEKWithMetadata, KeyError> dekResult = keyManager.getActiveDEK(context);
            if (dekResult.isFailure()) {
                KeyError keyError = dekResult.getError().orElseThrow();
                EncryptionError error = EncryptionError.of(
                    "KEY_UNAVAILABLE",
                    "Failed to retrieve active DEK: " + keyError.getMessage(),
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
                EncryptionError error = EncryptionError.of(
                    "IV_GENERATION_FAILED",
                    "Failed to generate IV: " + ivError.getMessage()
                );
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
                DecryptionError formatError = formatResult.getError().orElseThrow();
                EncryptionError error = EncryptionError.of(
                    "FORMAT_ERROR",
                    "Failed to format ciphertext: " + formatError.getMessage()
                );
                logEncryptionFailure(context, keyId, error);
                return Result.failure(error);
            }

            Ciphertext ciphertext = formatResult.getValue().orElseThrow();

            // 6. Log successful operation
            logEncryptionSuccess(context, keyId);

            return Result.success(ciphertext);

        } catch (Exception e) {
            EncryptionError error = EncryptionError.of(
                "ENCRYPTION_FAILED",
                "Unexpected error during encryption: " + e.getMessage(),
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

        Instant startTime = Instant.now();
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
                DecryptionError error = DecryptionError.of(
                    "UNSUPPORTED_VERSION",
                    "Unsupported ciphertext version: 0x" + String.format("%02X", parsed.getVersion())
                );
                logDecryptionFailure(context, keyId, error);
                return Result.failure(error);
            }

            if (parsed.getAlgorithm() != EncryptionAlgorithm.AES_256_GCM) {
                DecryptionError error = DecryptionError.of(
                    "UNSUPPORTED_ALGORITHM",
                    "Unsupported algorithm: " + parsed.getAlgorithm()
                );
                logDecryptionFailure(context, keyId, error);
                return Result.failure(error);
            }

            // 3. Get DEK by key ID from KeyManager
            Result<DEKWithMetadata, KeyError> dekResult = keyManager.getDEK(keyId);
            if (dekResult.isFailure()) {
                KeyError keyError = dekResult.getError().orElseThrow();
                DecryptionError error = DecryptionError.of(
                    "KEY_NOT_FOUND",
                    "Failed to retrieve DEK: " + keyError.getMessage(),
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
                "DECRYPTION_FAILED",
                "Unexpected error during decryption: " + e.getMessage(),
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
                    "KEY_UNAVAILABLE",
                    "Failed to retrieve active DEK for batch: " + keyError.getMessage(),
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
                    return Result.failure(EncryptionError.of(
                        "INVALID_PLAINTEXT",
                        "Plaintext in batch cannot be null"
                    ));
                }

                // Generate unique IV for this item
                Result<IV, IVCounterError> ivResult = ivCounter.generateIV(keyId);
                if (ivResult.isFailure()) {
                    IVCounterError ivError = ivResult.getError().orElseThrow();
                    return Result.failure(EncryptionError.of(
                        "IV_GENERATION_FAILED",
                        "Failed to generate IV in batch: " + ivError.getMessage()
                    ));
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
                    DecryptionError formatError = formatResult.getError().orElseThrow();
                    return Result.failure(EncryptionError.of(
                        "FORMAT_ERROR",
                        "Failed to format ciphertext in batch: " + formatError.getMessage()
                    ));
                }

                ciphertexts.add(formatResult.getValue().orElseThrow());
            }

            // Log batch operation
            logEncryptionSuccess(context, keyId, plaintexts.size());

            return Result.success(ciphertexts);

        } catch (Exception e) {
            return Result.failure(EncryptionError.of(
                "BATCH_ENCRYPTION_FAILED",
                "Unexpected error during batch encryption: " + e.getMessage(),
                e
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
            List<String> plaintexts = new ArrayList<>(ciphertexts.size());

            // Decrypt each ciphertext (may use different DEKs due to rotation)
            for (Ciphertext ciphertext : ciphertexts) {
                if (ciphertext == null) {
                    return Result.failure(DecryptionError.of(
                        "INVALID_CIPHERTEXT",
                        "Ciphertext in batch cannot be null"
                    ));
                }

                Result<String, DecryptionError> decryptResult = decrypt(ciphertext, context);
                if (decryptResult.isFailure()) {
                    return Result.failure(decryptResult.getError().orElseThrow());
                }

                plaintexts.add(decryptResult.getValue().orElseThrow());
            }

            return Result.success(plaintexts);

        } catch (Exception e) {
            return Result.failure(DecryptionError.of(
                "BATCH_DECRYPTION_FAILED",
                "Unexpected error during batch decryption: " + e.getMessage(),
                e
            ));
        }
    }

    @Override
    public Result<BlindIndex, EncryptionError> generateBlindIndex(String plaintext, String recordSalt) {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        Objects.requireNonNull(recordSalt, "Record salt cannot be null");
        return blindIndexService.generateBlindIndex(plaintext, recordSalt);
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
            return Result.failure(EncryptionError.of(
                "ENCRYPTION_FAILED",
                "AES-256-GCM encryption failed: " + e.getMessage(),
                e
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
            // Authentication tag verification failed - tampering detected
            logTamperingDetected(context, keyId);
            return Result.failure(DecryptionError.of(
                "TAMPERING_DETECTED",
                "Authentication tag verification failed - data may have been tampered with"
            ));
        } catch (Exception e) {
            return Result.failure(DecryptionError.of(
                "DECRYPTION_FAILED",
                "AES-256-GCM decryption failed: " + e.getMessage(),
                e
            ));
        }
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
        DecryptionEvent event = DecryptionEvent.builder()
            .timestamp(Instant.now())
            .context(context)
            .serviceIdentity(SERVICE_IDENTITY)
            .keyId(keyId)
            .success(true)
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
