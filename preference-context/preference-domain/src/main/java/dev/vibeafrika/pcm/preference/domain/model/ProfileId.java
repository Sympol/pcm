package dev.vibeafrika.pcm.preference.domain.model;

import java.util.Objects;
import java.util.UUID;

/**
 * ProfileId value object - wraps UUID with domain meaning.
 */
public final class ProfileId {
    private final UUID value;

    private ProfileId(UUID value) {
        this.value = Objects.requireNonNull(value, "ProfileId value cannot be null");
    }

    public static ProfileId of(UUID value) {
        return new ProfileId(value);
    }

    public static ProfileId generate() {
        return new ProfileId(UUID.randomUUID());
    }

    public UUID getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ProfileId)) return false;
        ProfileId profileId = (ProfileId) o;
        return value.equals(profileId.value);
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
