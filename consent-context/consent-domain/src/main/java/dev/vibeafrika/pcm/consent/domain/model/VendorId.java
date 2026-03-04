package dev.vibeafrika.pcm.consent.domain.model;

import io.github.sympol.pure.asserts.Assert;

import java.util.Objects;

/**
 * VendorId value object - IAB TCF vendor identifier.
 * Framework-agnostic, immutable.
 */
public final class VendorId {
    private final Integer value;

    private VendorId(Integer value) {
        this.value = Assert.field("vendorId", value)
            .min(1)
            .value();
    }

    public static VendorId of(Integer value) {
        return new VendorId(value);
    }

    public Integer getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof VendorId)) return false;
        VendorId that = (VendorId) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
