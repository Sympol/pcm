package dev.vibeafrika.pcm.consent.domain.model;

import io.github.sympol.pure.asserts.Assert;

import java.util.Objects;

/**
 * PurposeId value object - IAB TCF purpose identifier.
 * Framework-agnostic, immutable.
 */
public final class PurposeId {
    private final Integer value;

    private PurposeId(Integer value) {
        this.value = Assert.field("purposeId", value)
            .min(1)
            .value();
    }

    public static PurposeId of(Integer value) {
        return new PurposeId(value);
    }

    public Integer getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PurposeId)) return false;
        PurposeId that = (PurposeId) o;
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
