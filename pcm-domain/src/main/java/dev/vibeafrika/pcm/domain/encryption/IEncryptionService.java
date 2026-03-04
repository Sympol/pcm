package dev.vibeafrika.pcm.domain.encryption;

import java.util.List;

/**
 * Domain interface for PII encryption operations.
 * 
 * This interface defines the contract for encrypting and decrypting PII data
 * using envelope encryption with AES-256-GCM. The implementation is provided
 * by the infrastructure layer, keeping the domain layer framework-agnostic.
 * 
 * All operations use the Result type for functional error handling without exceptions.
 * 
 */
public interface IEncryptionService {

    /**
     * Encrypts plaintext data using the active DEK for the given bounded context.
     * 
     * The encryption process:
     * 1. Retrieves the active DEK for the context from the KeyManager
     * 2. Generates a unique IV using counter-based approach
     * 3. Performs AES-256-GCM encryption
     * 4. Formats the result as: [version|algorithm_id|key_id|IV|ciphertext|auth_tag]
     * 5. Logs the operation via AuditLogger
     * 
     * @param plaintext the plaintext PII data to encrypt
     * @param context the bounded context (PROFILE, CONSENT, SEGMENT, PREFERENCE)
     * @return Result containing the Ciphertext on success, or EncryptionError on failure
     */
    Result<Ciphertext, EncryptionError> encrypt(String plaintext, BoundedContext context);

    /**
     * Decrypts ciphertext using the DEK identified in the ciphertext metadata.
     * 
     * The decryption process:
     * 1. Parses the ciphertext format to extract version, algorithm, key_id, IV, and auth_tag
     * 2. Validates the version and algorithm
     * 3. Retrieves the DEK by key_id from the KeyManager
     * 4. Performs AES-256-GCM decryption
     * 5. Verifies the authentication tag to detect tampering
     * 6. Logs the operation via AuditLogger
     * 
     * @param ciphertext the encrypted data to decrypt
     * @param context the bounded context (PROFILE, CONSENT, SEGMENT, PREFERENCE)
     * @return Result containing the plaintext String on success, or DecryptionError on failure
     */
    Result<String, DecryptionError> decrypt(Ciphertext ciphertext, BoundedContext context);

    /**
     * Encrypts multiple plaintext values in a single batch operation.
     * 
     * Batch operations are more efficient than individual encrypt calls because:
     * - The active DEK is retrieved once and reused for all encryptions
     * - Reduces overhead from repeated KeyManager and AuditLogger calls
     * - Maintains throughput above 100 fields per second (Requirement 10.4)
     * 
     * Each plaintext is encrypted independently with a unique IV, ensuring
     * that identical plaintexts produce different ciphertexts.
     * 
     * @param plaintexts the list of plaintext PII data to encrypt
     * @param context the bounded context (PROFILE, CONSENT, SEGMENT, PREFERENCE)
     * @return Result containing the list of Ciphertexts on success, or EncryptionError on failure
     */
    Result<List<Ciphertext>, EncryptionError> encryptBatch(List<String> plaintexts, BoundedContext context);

    /**
     * Decrypts multiple ciphertexts in a single batch operation.
     * 
     * Batch operations are more efficient than individual decrypt calls because:
     * - DEKs are retrieved once and cached for reuse across the batch
     * - Reduces overhead from repeated KeyManager and AuditLogger calls
     * - Maintains throughput above 100 fields per second (Requirement 10.4)
     * 
     * Each ciphertext may have been encrypted with a different DEK (due to key rotation),
     * so the implementation must handle multiple key_ids within a single batch.
     * 
     * @param ciphertexts the list of encrypted data to decrypt
     * @param context the bounded context (PROFILE, CONSENT, SEGMENT, PREFERENCE)
     * @return Result containing the list of plaintext Strings on success, or DecryptionError on failure
     */
    Result<List<String>, DecryptionError> decryptBatch(List<Ciphertext> ciphertexts, BoundedContext context);

    /**
     * Generates a blind index for searchable encryption.
     * 
     * Blind indexes enable exact-match searching on encrypted fields while
     * resisting frequency analysis and pattern matching attacks.
     * 
     * The blind index is computed as:
     * HMAC-SHA256(blind_index_key, global_salt || record_salt || normalized_plaintext)
     * 
     * Where:
     * - blind_index_key: A separate key stored in the KMS
     * - global_salt: A secret salt shared across all records (resists frequency analysis)
     * - record_salt: A unique salt per record (resists pattern matching)
     * - normalized_plaintext: Lowercase and trimmed plaintext
     * 
     * The same plaintext with different record salts produces different blind indexes,
     * preventing attackers from identifying duplicate values.
     * 
     * @param plaintext the plaintext value to generate a blind index for
     * @param recordSalt the unique per-record salt
     * @return Result containing the BlindIndex on success, or EncryptionError on failure
     */
    Result<BlindIndex, EncryptionError> generateBlindIndex(String plaintext, String recordSalt);
}
