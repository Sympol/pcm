package dev.vibeafrika.pcm.domain.encryption;

/**
 * Fine-grained permissions for the PII encryption system.
 *
 * <p>Permissions are assigned to {@link EncryptionRole}s to enforce the
 * principle of least privilege and separation of duties.
 */
public enum EncryptionPermission {

    // -------------------------------------------------------------------------
    // Encryption operations (DEVELOPER)
    // -------------------------------------------------------------------------

    /** Encrypt PII data using the active DEK. */
    ENCRYPT_DATA,

    /** Decrypt PII data using the DEK identified in the ciphertext. */
    DECRYPT_DATA,

    /** Generate a blind index for searchable encryption. */
    GENERATE_BLIND_INDEX,

    // -------------------------------------------------------------------------
    // Key lifecycle operations (KEY_OPERATOR)
    // -------------------------------------------------------------------------

    /** Rotate the active DEK for a bounded context. */
    ROTATE_DEK,

    /** Rotate the KEK for a bounded context. */
    ROTATE_KEK,

    /** Invalidate cached DEKs. */
    INVALIDATE_KEY_CACHE,

    /** Delete a user-specific DEK for cryptographic erasure (GDPR). */
    DELETE_USER_DEK,

    // -------------------------------------------------------------------------
    // KMS administration (CRYPTO_ADMIN)
    // -------------------------------------------------------------------------

    /** Configure KMS policies and manage KMS infrastructure. */
    CONFIGURE_KMS_POLICY,

    // -------------------------------------------------------------------------
    // Read-only operations (AUDITOR + CRYPTO_ADMIN)
    // -------------------------------------------------------------------------

    /** Read audit logs. */
    VIEW_AUDIT_LOGS,

    /** Read key metadata (IDs, status, rotation dates). Does NOT expose key material. */
    VIEW_KEY_METADATA
}
