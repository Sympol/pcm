package dev.vibeafrika.pcm.common.domain;

import java.util.Objects;
import java.util.UUID;

/**
 * Value Object representing a Tenant ID for multi-tenancy support.
 */
public final class TenantId implements ValueObject {
    
    private final String value;
    
    private TenantId(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Tenant ID cannot be null or blank");
        }
        this.value = value;
    }
    
    public static TenantId of(String value) {
        return new TenantId(value);
    }
    
    public static TenantId generate() {
        return new TenantId(UUID.randomUUID().toString());
    }
    
    @Override
    public String toString() {
        return value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof TenantId tenantId)) return false;
        return Objects.equals(value, tenantId.value);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value);
    }
}
