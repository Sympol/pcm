package dev.vibeafrika.pcm.consent.domain.model;

import io.github.sympol.pure.asserts.Assert;

import java.util.Objects;
import java.util.UUID;

/**
 * ConsentId value object - wraps UUID with domain meaning.
 * Framework-agnostic, immutable.
 */
public final class ConsentId {
    private final UUID value;

    private ConsentId(UUID value) {
        this.value = Assert.field("consentId", value)
            .notNull()
            .value();
    }

    public static ConsentId of(UUID value) {
        return new ConsentId(value);
    }

    public static ConsentId generate() {
        return new ConsentId(UUID.randomUUID());
    }

    public UUID getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ConsentId)) return false;
        ConsentId that = (ConsentId) o;
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
