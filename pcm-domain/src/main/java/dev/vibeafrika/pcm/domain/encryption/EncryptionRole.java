package dev.vibeafrika.pcm.domain.encryption;

import java.util.EnumSet;
import java.util.Set;

/**
 * Defines the RBAC roles for the PII encryption system.
 *
 * <p>Roles enforce separation of duties so that no single role has full access
 * to all encryption operations:
 *
 * <ul>
 *   <li>{@link #CRYPTO_ADMIN} – configures KMS policies; cannot rotate keys</li>
 *   <li>{@link #KEY_OPERATOR} – rotates keys and manages lifecycle; cannot modify KMS policies</li>
 *   <li>{@link #AUDITOR} – read-only access to audit logs and key metadata; no write operations</li>
 *   <li>{@link #DEVELOPER} – uses encryption/decryption services; cannot manage keys</li>
 * </ul>
 */
public enum EncryptionRole {

    /**
     * Configures KMS policies and manages KMS infrastructure.
     * Cannot rotate keys or perform key lifecycle operations.
     */
    CRYPTO_ADMIN(EnumSet.of(
            EncryptionPermission.CONFIGURE_KMS_POLICY,
            EncryptionPermission.VIEW_KEY_METADATA,
            EncryptionPermission.VIEW_AUDIT_LOGS
    )),

    /**
     * Rotates keys and manages key lifecycle.
     * Cannot modify KMS policies.
     */
    KEY_OPERATOR(EnumSet.of(
            EncryptionPermission.ROTATE_DEK,
            EncryptionPermission.ROTATE_KEK,
            EncryptionPermission.VIEW_KEY_METADATA,
            EncryptionPermission.INVALIDATE_KEY_CACHE,
            EncryptionPermission.DELETE_USER_DEK
    )),

    /**
     * Read-only access to audit logs and key metadata.
     * Cannot perform any write operations.
     */
    AUDITOR(EnumSet.of(
            EncryptionPermission.VIEW_AUDIT_LOGS,
            EncryptionPermission.VIEW_KEY_METADATA
    )),

    /**
     * Uses encryption and decryption services.
     * Cannot manage keys or access audit logs.
     */
    DEVELOPER(EnumSet.of(
            EncryptionPermission.ENCRYPT_DATA,
            EncryptionPermission.DECRYPT_DATA,
            EncryptionPermission.GENERATE_BLIND_INDEX
    ));

    private final Set<EncryptionPermission> permissions;

    EncryptionRole(Set<EncryptionPermission> permissions) {
        this.permissions = permissions;
    }

    /**
     * Returns the set of permissions granted to this role.
     */
    public Set<EncryptionPermission> getPermissions() {
        return permissions;
    }

    /**
     * Returns {@code true} if this role has the given permission.
     */
    public boolean hasPermission(EncryptionPermission permission) {
        return permissions.contains(permission);
    }
}
