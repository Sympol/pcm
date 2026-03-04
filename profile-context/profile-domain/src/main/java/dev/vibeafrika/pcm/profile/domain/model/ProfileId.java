package dev.vibeafrika.pcm.profile.domain.model;

import java.util.Objects;
import java.util.UUID;

/**
 * ProfileId value object - wraps UUID with domain meaning.
 * Represents the unique identifier for a Profile aggregate.
 */
public final class ProfileId {
    private final UUID value;

    private ProfileId(UUID value) {
        this.value = Objects.requireNonNull(value, "ProfileId value cannot be null");
    }

    /**
     * Create a ProfileId from a UUID.
     * 
     * @param value The UUID value
     * @return A ProfileId instance
     */
    public static ProfileId of(UUID value) {
        return new ProfileId(value);
    }

    /**
     * Generate a new random ProfileId.
     * 
     * @return A new ProfileId with random UUID
     */
    public static ProfileId generate() {
        return new ProfileId(UUID.randomUUID());
    }

    /**
     * Get the underlying UUID value.
     * 
     * @return The UUID value
     */
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
