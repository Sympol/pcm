package dev.vibeafrika.pcm.domain.encryption;

/**
 * Classifies non-cryptographic secrets managed through the unified secret management system.
 *
 * <p>All secret types are stored in KMS with the same encryption standards as DEKs
 * and are subject to the same access control policies.
 */
public enum SecretType {

    /**
     * API tokens used for authenticating with external services.
     * Rotated every 90 days.
     */
    API_TOKEN,

    /**
     * Database credentials (username/password pairs or connection strings).
     * Rotated quarterly.
     */
    DATABASE_CREDENTIAL,

    /**
     * Service-to-service authentication secrets (shared secrets, HMAC keys, etc.).
     * Rotated quarterly.
     */
    SERVICE_SECRET
}
