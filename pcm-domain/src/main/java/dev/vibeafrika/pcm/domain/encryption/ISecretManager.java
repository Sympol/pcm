package dev.vibeafrika.pcm.domain.encryption;

import java.util.UUID;

/**
 * Domain interface for unified secret management.
 *
 * <p>Manages non-cryptographic secrets (API tokens, database credentials,
 * service-to-service authentication secrets) with the same rigor as encryption keys:
 * <ul>
 *   <li>Secrets are stored in KMS with the same encryption standards as DEKs</li>
 *   <li>Secrets are cached with the same TTL and eviction policies as DEKs</li>
 *   <li>All secret access is audit-logged with the same detail as key access</li>
 *   <li>The same access control policies apply to secrets as to encryption keys</li>
 * </ul>
 *
 * <p>Rotation schedules:
 * <ul>
 *   <li>API tokens: every 90 days</li>
 *   <li>Database credentials: quarterly (every 90 days)</li>
 *   <li>Service secrets: quarterly (every 90 days)</li>
 * </ul>
 */
public interface ISecretManager {

    /**
     * Stores a secret in KMS and returns its assigned ID.
     *
     * <p>The secret value is encrypted in KMS using the same standards as DEKs.
     * The plaintext secret value is never logged.
     *
     * @param secretName   a human-readable identifier for the secret (e.g. "stripe-api-key")
     * @param secretValue  the plaintext secret value to store
     * @param secretType   the type of secret (API_TOKEN, DATABASE_CREDENTIAL, SERVICE_SECRET)
     * @param context      the bounded context that owns this secret
     * @return Result containing the new secret's UUID, or KeyError if storage fails
     */
    Result<UUID, KeyError> storeSecret(String secretName, String secretValue,
                                       SecretType secretType, BoundedContext context);

    /**
     * Retrieves a secret value from KMS (or cache).
     *
     * <p>Follows the same cache-first pattern as DEK retrieval: returns the cached
     * value if present and not expired, otherwise fetches from KMS and caches the result.
     *
     * @param secretId the UUID of the secret to retrieve
     * @return Result containing the plaintext secret value, or KeyError if retrieval fails
     */
    Result<String, KeyError> getSecret(UUID secretId);

    /**
     * Rotates a secret by storing a new value and marking the old one as ROTATED.
     *
     * <p>The old secret remains retrievable until explicitly deleted, allowing
     * in-flight requests to complete. The new secret becomes active immediately.
     *
     * @param secretId       the UUID of the secret to rotate
     * @param newSecretValue the new plaintext secret value
     * @return Result containing the new secret's UUID, or KeyError if rotation fails
     */
    Result<UUID, KeyError> rotateSecret(UUID secretId, String newSecretValue);

    /**
     * Deletes a secret from KMS and invalidates it from cache.
     *
     * @param secretId the UUID of the secret to delete
     * @return Result containing Unit on success, or KeyError if deletion fails
     */
    Result<Unit, KeyError> deleteSecret(UUID secretId);

    /**
     * Returns the metadata for a secret without exposing its value.
     *
     * @param secretId the UUID of the secret
     * @return Result containing the secret metadata, or KeyError if not found
     */
    Result<SecretMetadata, KeyError> getSecretMetadata(UUID secretId);
}
