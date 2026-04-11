package dev.vibeafrika.pcm.domain.encryption;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * Represents the machine identity of a service requesting encryption operations.
 *
 * <p>Direct human access to encryption keys is prohibited.
 * All key requests must be authenticated using machine identity.
 *
 * <p>A {@code ServiceIdentity} carries:
 * <ul>
 *   <li>A unique service name (e.g. {@code "profile-service"})</li>
 *   <li>The set of {@link EncryptionRole}s granted to this service</li>
 *   <li>A flag indicating whether this is a human identity (always rejected for key ops)</li>
 * </ul>
 */
public final class ServiceIdentity {

    private final String serviceName;
    private final Set<EncryptionRole> roles;
    private final boolean humanIdentity;

    private ServiceIdentity(String serviceName, Set<EncryptionRole> roles, boolean humanIdentity) {
        this.serviceName = Objects.requireNonNull(serviceName, "Service name cannot be null");
        if (serviceName.isBlank()) {
            throw new IllegalArgumentException("Service name cannot be blank");
        }
        this.roles = roles != null ? Collections.unmodifiableSet(roles) : Collections.emptySet();
        this.humanIdentity = humanIdentity;
    }

    /**
     * Creates a machine service identity with the given roles.
     */
    public static ServiceIdentity machine(String serviceName, Set<EncryptionRole> roles) {
        return new ServiceIdentity(serviceName, roles, false);
    }

    /**
     * Creates a human identity (will be rejected for all key operations).
     */
    public static ServiceIdentity human(String name) {
        return new ServiceIdentity(name, Collections.emptySet(), true);
    }

    public String getServiceName() {
        return serviceName;
    }

    public Set<EncryptionRole> getRoles() {
        return roles;
    }

    /**
     * Returns {@code true} if this identity represents a human user.
     * Human identities are prohibited from accessing encryption keys.
     */
    public boolean isHumanIdentity() {
        return humanIdentity;
    }

    /**
     * Returns {@code true} if this identity holds the given role.
     */
    public boolean hasRole(EncryptionRole role) {
        return roles.contains(role);
    }

    /**
     * Returns {@code true} if this identity has the given permission through any of its roles.
     */
    public boolean hasPermission(EncryptionPermission permission) {
        return roles.stream().anyMatch(r -> r.hasPermission(permission));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServiceIdentity that = (ServiceIdentity) o;
        return humanIdentity == that.humanIdentity
                && Objects.equals(serviceName, that.serviceName)
                && Objects.equals(roles, that.roles);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serviceName, roles, humanIdentity);
    }

    @Override
    public String toString() {
        return "ServiceIdentity{name='" + serviceName + "', roles=" + roles
                + ", human=" + humanIdentity + "}";
    }
}
