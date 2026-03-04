package dev.vibeafrika.pcm.preference.domain.model;

import io.github.sympol.pure.asserts.Assert;
import java.util.Objects;
import java.util.UUID;

/**
 * PreferenceId value object - wraps UUID with domain meaning.
 */
public final class PreferenceId {
    private final UUID value;

    private PreferenceId(UUID value) {
        this.value = Assert.field("preferenceId", value)
            .notNull()
            .value();
    }

    public static PreferenceId of(UUID value) {
        return new PreferenceId(value);
    }

    public static PreferenceId generate() {
        return new PreferenceId(UUID.randomUUID());
    }

    public UUID getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PreferenceId)) return false;
        PreferenceId that = (PreferenceId) o;
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
