package dev.vibeafrika.pcm.consent.domain.model;

import io.github.sympol.pure.asserts.Assert;

import java.util.Objects;

/**
 * ConsentPurpose value object - represents the purpose for which consent is granted.
 * Framework-agnostic, immutable.
 */
public final class ConsentPurpose {
    private final String value;

    private ConsentPurpose(String value) {
        this.value = Assert.field("consentPurpose", value)
            .notBlank()
            .minLength(3)
            .maxLength(200)
            .value();
    }

    public static ConsentPurpose of(String value) {
        return new ConsentPurpose(value);
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ConsentPurpose)) return false;
        ConsentPurpose that = (ConsentPurpose) o;
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
