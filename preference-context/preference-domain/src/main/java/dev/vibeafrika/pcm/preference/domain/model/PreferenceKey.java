package dev.vibeafrika.pcm.preference.domain.model;

import io.github.sympol.pure.asserts.Assert;
import java.util.Objects;

/**
 * PreferenceKey value object - represents a preference setting key with validation.
 */
public final class PreferenceKey {
    private final String value;

    private PreferenceKey(String value) {
        this.value = Assert.field("preferenceKey", value)
            .notBlank()
            .maxLength(100)
            .value();
    }

    public static PreferenceKey of(String value) {
        return new PreferenceKey(value);
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PreferenceKey)) return false;
        PreferenceKey that = (PreferenceKey) o;
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
