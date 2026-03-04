package dev.vibeafrika.pcm.consent.domain.model;

import io.github.sympol.pure.asserts.Assert;

import java.util.Objects;

/**
 * TCString value object - IAB TCF Transparency & Consent String.
 * Framework-agnostic, immutable.
 */
public final class TCString {
    private final String value;

    private TCString(String value) {
        this.value = Assert.field("tcString", value)
            .notBlank()
            .minLength(10)
            .value();
    }

    public static TCString of(String value) {
        return new TCString(value);
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TCString)) return false;
        TCString that = (TCString) o;
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
