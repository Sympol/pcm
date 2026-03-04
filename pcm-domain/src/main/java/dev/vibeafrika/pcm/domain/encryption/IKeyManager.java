package dev.vibeafrika.pcm.domain.encryption;

import java.util.UUID;

/**
 * Domain interface for managing encryption keys in the envelope encryption pattern.
 * 
 * <p>The KeyManager is responsible for:
 * <ul>
 *   <li>Managing the KEK/DEK hierarchy (Key Encryption Keys and Data Encryption Keys)</li>
 *   <li>Caching decrypted DEKs in memory for performance optimization</li>
 *   <li>Coordinating with KMS for key operations</li>
 *   <li>Implementing automatic key rotation policies</li>
 *   <li>Enforcing key isolation by bounded context and environment</li>
 *   <li>Supporting cryptographic erasure for GDPR compliance</li>
 * </ul>
 * 
 * <p>Key hierarchy:
 * <pre>
 * Root KEK (per environment: DEV, STAGING, PROD)
 * ├── {env}.{context}.kek.{uuid}
 * │   ├── {env}.{context}.dek.context.{uuid}
 * │   └── {env}.{context}.dek.user.{user_id}
 * </pre>
 * 
 */
public interface IKeyManager {

    /**
     * Retrieves the active DEK for new encryption operations in the given context.
     * 
     * <p>Returns a cached DEK if available (with TTL validation), otherwise fetches
     * the encrypted DEK from KMS, decrypts it using the context KEK, and caches it.
     * 
     * <p>The active DEK is the most recent DEK marked as ACTIVE for the context.
     * All new encryption operations should use the active DEK.
     * 
     * @param context the bounded context (Profile, Consent, Segment, or Preference)
     * @return Result containing DEK with metadata, or KeyError if retrieval fails
     */
    Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context);

    /**
     * Retrieves a specific DEK by its ID for decryption operations.
     * 
     * <p>Returns a cached DEK if available (with TTL validation), otherwise fetches
     * the encrypted DEK from KMS, decrypts it using the appropriate KEK, and caches it.
     * 
     * <p>This method is used during decryption when the ciphertext contains a key ID
     * that may reference a rotated (non-active) DEK.
     * 
     * @param keyId the UUID of the DEK to retrieve
     * @return Result containing DEK with metadata, or KeyError if retrieval fails
     */
    Result<DEKWithMetadata, KeyError> getDEK(UUID keyId);

    /**
     * Generates a new DEK, encrypts it with the context KEK, and stores it in KMS.
     * Marks the new DEK as active for the context.
     * 
     * <p>DEK rotation is triggered by:
     * <ul>
     *   <li>Automatic rotation after 90 days since DEK creation</li>
     *   <li>Automatic rotation after 1 terabyte of data encrypted with the DEK</li>
     *   <li>Automatic rotation after 2^32 encryption operations with the DEK</li>
     *   <li>Emergency rotation when key compromise is suspected</li>
     *   <li>Manual rotation for compliance requirements</li>
     * </ul>
     * 
     * <p>The previous DEK is marked as ROTATED but remains available for decrypting
     * existing data. The IV counter is reset for the new DEK.
     * 
     * @param context the bounded context for which to rotate the DEK
     * @return Result containing the new DEK's UUID, or KeyError if rotation fails
     */
    Result<UUID, KeyError> rotateDEK(BoundedContext context);

    /**
     * Rotates the KEK for a bounded context.
     * Re-encrypts all DEKs with the new KEK.
     * 
     * <p>KEK rotation is typically performed:
     * <ul>
     *   <li>Annually as part of regular key lifecycle management</li>
     *   <li>When required by compliance policies</li>
     *   <li>When KEK compromise is suspected</li>
     * </ul>
     * 
     * <p>This operation:
     * <ol>
     *   <li>Generates a new KEK in KMS</li>
     *   <li>Retrieves all DEKs encrypted with the old KEK</li>
     *   <li>Re-encrypts each DEK with the new KEK</li>
     *   <li>Updates DEK metadata with the new KEK ID</li>
     *   <li>Marks the old KEK as ROTATED</li>
     *   <li>Invalidates all cached DEKs for the context</li>
     * </ol>
     * 
     * @param context the bounded context for which to rotate the KEK
     * @return Result containing the new KEK's UUID, or KeyError if rotation fails
     */
    Result<UUID, KeyError> rotateKEK(BoundedContext context);

    /**
     * Invalidates cached DEKs, forcing fresh retrieval from KMS.
     * 
     * <p>If keyId is provided, only that specific DEK is invalidated from cache.
     * If keyId is null, all cached DEKs are invalidated.
     * 
     * <p>This method securely wipes key material from memory before eviction.
     * 
     * <p>Cache invalidation is triggered:
     * <ul>
     *   <li>After DEK rotation (invalidate the rotated DEK)</li>
     *   <li>After KEK rotation (invalidate all DEKs for the context)</li>
     *   <li>When key compromise is suspected</li>
     *   <li>For testing and debugging purposes</li>
     * </ul>
     * 
     * @param keyId the UUID of the DEK to invalidate, or null to invalidate all
     * @return Result containing void on success, or KeyError if invalidation fails
     */
    Result<Void, KeyError> invalidateCache(UUID keyId);

    /**
     * Deletes a user-specific DEK for cryptographic erasure (GDPR right to deletion).
     * 
     * <p>This implements the "right to be forgotten" under GDPR Article 17 by making
     * the user's encrypted data permanently unrecoverable through key deletion.
     * 
     * <p>This operation:
     * <ol>
     *   <li>Identifies the user-specific DEK</li>
     *   <li>Deletes the DEK from KMS</li>
     *   <li>Invalidates the DEK from cache</li>
     *   <li>Verifies the deletion</li>
     *   <li>Generates a signed deletion certificate as proof</li>
     *   <li>Logs the deletion event</li>
     * </ol>
     * 
     * <p>After deletion, any data encrypted with this DEK becomes permanently
     * unrecoverable, providing cryptographic proof of data erasure.
     * 
     * @param userId the user ID whose DEK should be deleted
     * @param context the bounded context containing the user's data
     * @return Result containing a deletion certificate, or KeyError if deletion fails
     */
    Result<DeletionCertificate, KeyError> deleteUserDEK(String userId, BoundedContext context);
}
