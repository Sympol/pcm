package dev.vibeafrika.pcm.domain.encryption;

import java.util.Objects;

/**
 * Represents an access control denial for an encryption operation.
 *
 * <p>Returned when a {@link ServiceIdentity} attempts an operation it is not
 * authorized to perform.
 */
public final class AccessDeniedError {

    private final String code;
    private final String message;
    private final String serviceIdentity;
    private final EncryptionPermission requiredPermission;

    private AccessDeniedError(String code, String message,
                               String serviceIdentity,
                               EncryptionPermission requiredPermission) {
        this.code = Objects.requireNonNull(code, "Code cannot be null");
        this.message = Objects.requireNonNull(message, "Message cannot be null");
        this.serviceIdentity = serviceIdentity;
        this.requiredPermission = requiredPermission;
    }

    public static AccessDeniedError of(String serviceIdentity, EncryptionPermission permission) {
        return new AccessDeniedError(
                "ACCESS_DENIED",
                "Service '" + serviceIdentity + "' does not have permission: " + permission,
                serviceIdentity,
                permission
        );
    }

    public static AccessDeniedError humanAccessDenied(String identity) {
        return new AccessDeniedError(
                "HUMAN_ACCESS_DENIED",
                "Direct human access to encryption keys is prohibited. Identity: " + identity,
                identity,
                null
        );
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public String getServiceIdentity() {
        return serviceIdentity;
    }

    public EncryptionPermission getRequiredPermission() {
        return requiredPermission;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AccessDeniedError that = (AccessDeniedError) o;
        return Objects.equals(code, that.code)
                && Objects.equals(serviceIdentity, that.serviceIdentity)
                && requiredPermission == that.requiredPermission;
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, serviceIdentity, requiredPermission);
    }

    @Override
    public String toString() {
        return "AccessDeniedError{code='" + code + "', service='" + serviceIdentity
                + "', permission=" + requiredPermission + "}";
    }
}
