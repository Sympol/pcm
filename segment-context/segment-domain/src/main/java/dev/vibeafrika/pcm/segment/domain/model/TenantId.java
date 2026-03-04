package dev.vibeafrika.pcm.segment.domain.model;

import io.github.sympol.pure.asserts.Assert;
import java.util.Objects;

/**
 * TenantId value object - represents a tenant identifier with validation.
 */
public final class TenantId {
    private final String value;

    private TenantId(String value) {
        this.value = Assert.field("tenantId", value)
            .notBlank()
            .maxLength(100)
            .value();
    }

    public static TenantId of(String value) {
        return new TenantId(value);
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TenantId)) return false;
        TenantId that = (TenantId) o;
        return value.equals(that.value);
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
