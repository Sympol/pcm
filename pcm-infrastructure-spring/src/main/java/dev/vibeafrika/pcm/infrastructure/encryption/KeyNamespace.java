package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.BoundedContext;
import dev.vibeafrika.pcm.domain.encryption.Environment;

import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Utility class for generating and parsing key namespace identifiers.
 *
 * <p>Enforces the key namespace format:
 * {@code {environment}.{bounded_context}.{key_type}.{key_id}}
 *
 * <p>Examples:
 * <ul>
 *   <li>{@code prod.profile.kek.550e8400-e29b-41d4-a716-446655440000}</li>
 *   <li>{@code prod.profile.dek.context.550e8400-e29b-41d4-a716-446655440000}</li>
 *   <li>{@code dev.consent.dek.user.550e8400-e29b-41d4-a716-446655440000}</li>
 * </ul>
 *
 * <p>This class ensures that keys from different environments cannot be confused
 * or reused across environments (Requirements 17.1, 17.2, 17.3, 17.4).
 */
public final class KeyNamespace {

    /** Key type identifier for Key Encryption Keys. */
    public static final String KEY_TYPE_KEK = "kek";

    /** Key type identifier for context-level Data Encryption Keys. */
    public static final String KEY_TYPE_DEK_CONTEXT = "dek.context";

    /** Key type identifier for user-level Data Encryption Keys. */
    public static final String KEY_TYPE_DEK_USER = "dek.user";

    /** Pattern for validating namespace format: {env}.{context}.{key_type}.{uuid} */
    private static final Pattern NAMESPACE_PATTERN = Pattern.compile(
        "^(dev|staging|prod)\\.[a-z]+\\.(kek|dek\\.context|dek\\.user)\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    );

    private KeyNamespace() {
        // Utility class - no instantiation
    }

    /**
     * Generates a namespaced key ID for a KEK.
     *
     * <p>Format: {@code {environment}.{bounded_context}.kek.{uuid}}
     *
     * @param environment the deployment environment
     * @param context     the bounded context
     * @param keyId       the unique key identifier
     * @return the namespaced key ID string
     */
    public static String forKEK(Environment environment, BoundedContext context, UUID keyId) {
        Objects.requireNonNull(environment, "Environment cannot be null");
        Objects.requireNonNull(context, "BoundedContext cannot be null");
        Objects.requireNonNull(keyId, "Key ID cannot be null");
        return buildNamespace(environment, context, KEY_TYPE_KEK, keyId);
    }

    /**
     * Generates a namespaced key ID for a context-level DEK.
     *
     * <p>Format: {@code {environment}.{bounded_context}.dek.context.{uuid}}
     *
     * @param environment the deployment environment
     * @param context     the bounded context
     * @param keyId       the unique key identifier
     * @return the namespaced key ID string
     */
    public static String forContextDEK(Environment environment, BoundedContext context, UUID keyId) {
        Objects.requireNonNull(environment, "Environment cannot be null");
        Objects.requireNonNull(context, "BoundedContext cannot be null");
        Objects.requireNonNull(keyId, "Key ID cannot be null");
        return buildNamespace(environment, context, KEY_TYPE_DEK_CONTEXT, keyId);
    }

    /**
     * Generates a namespaced key ID for a user-level DEK.
     *
     * <p>Format: {@code {environment}.{bounded_context}.dek.user.{uuid}}
     *
     * @param environment the deployment environment
     * @param context     the bounded context
     * @param keyId       the unique key identifier
     * @return the namespaced key ID string
     */
    public static String forUserDEK(Environment environment, BoundedContext context, UUID keyId) {
        Objects.requireNonNull(environment, "Environment cannot be null");
        Objects.requireNonNull(context, "BoundedContext cannot be null");
        Objects.requireNonNull(keyId, "Key ID cannot be null");
        return buildNamespace(environment, context, KEY_TYPE_DEK_USER, keyId);
    }

    /**
     * Validates that a namespace string follows the required format.
     *
     * @param namespace the namespace string to validate
     * @return {@code true} if the namespace is valid, {@code false} otherwise
     */
    public static boolean isValid(String namespace) {
        if (namespace == null || namespace.isBlank()) {
            return false;
        }
        return NAMESPACE_PATTERN.matcher(namespace).matches();
    }

    /**
     * Extracts the environment from a namespace string.
     *
     * @param namespace the namespace string
     * @return the environment identifier
     * @throws IllegalArgumentException if the namespace is invalid
     */
    public static Environment extractEnvironment(String namespace) {
        Objects.requireNonNull(namespace, "Namespace cannot be null");
        String[] parts = namespace.split("\\.", 2);
        if (parts.length < 1) {
            throw new IllegalArgumentException("Invalid namespace format: " + namespace);
        }
        return Environment.valueOf(parts[0].toUpperCase());
    }

    /**
     * Extracts the UUID from a namespace string.
     *
     * @param namespace the namespace string
     * @return the UUID at the end of the namespace
     * @throws IllegalArgumentException if the namespace is invalid
     */
    public static UUID extractKeyId(String namespace) {
        Objects.requireNonNull(namespace, "Namespace cannot be null");
        int lastDot = namespace.lastIndexOf('.');
        if (lastDot < 0 || lastDot == namespace.length() - 1) {
            throw new IllegalArgumentException("Invalid namespace format: " + namespace);
        }
        return UUID.fromString(namespace.substring(lastDot + 1));
    }

    /**
     * Builds the namespace string from its components.
     */
    private static String buildNamespace(Environment environment, BoundedContext context,
                                          String keyType, UUID keyId) {
        return environment.name().toLowerCase() + "." +
               context.name().toLowerCase() + "." +
               keyType + "." +
               keyId;
    }
}
