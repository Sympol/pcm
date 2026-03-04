package dev.vibeafrika.pcm.consent.domain.model;

import io.github.sympol.pure.asserts.Assert;

import java.util.Objects;

/**
 * ConsentScope value object - represents the scope of consent.
 * Framework-agnostic, immutable.
 */
public final class ConsentScope {
    private final String value;

    private ConsentScope(String value) {
        this.value = Assert.field("consentScope", value)
            .notBlank()
            .minLength(3)
            .maxLength(200)
            .value();
    }

    public static ConsentScope of(String value) {
        return new ConsentScope(value);
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ConsentScope)) return false;
        ConsentScope that = (ConsentScope) o;
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
