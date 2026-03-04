package dev.vibeafrika.pcm.profile.domain.model;

import io.github.sympol.pure.asserts.Assert;
import java.util.Objects;

/**
 * TenantId value object - represents a tenant identifier with validation.
 * Maximum length is 100 characters.
 */
public final class TenantId {
    private final String value;

    private TenantId(String value) {
        this.value = Assert.field("tenantId", value)
            .notBlank()
            .maxLength(100)
            .value();
    }

    /**
     * Create a TenantId from a string value.
     * 
     * @param value The tenant ID string (max 100 chars)
     * @return A validated TenantId instance
     */
    public static TenantId of(String value) {
        return new TenantId(value);
    }

    /**
     * Get the tenant ID value.
     * 
     * @return The tenant ID string
     */
    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TenantId)) return false;
        TenantId tenantId = (TenantId) o;
        return value.equals(tenantId.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
