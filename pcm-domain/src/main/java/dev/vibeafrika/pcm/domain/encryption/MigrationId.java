package dev.vibeafrika.pcm.domain.encryption;

import java.util.Objects;
import java.util.UUID;

/**
 * Value object representing a unique identifier for an algorithm migration.
 */
public final class MigrationId {

    private final UUID value;

    private MigrationId(UUID value) {
        this.value = Objects.requireNonNull(value, "MigrationId value cannot be null");
    }

    public static MigrationId of(UUID value) {
        return new MigrationId(value);
    }

    public static MigrationId generate() {
        return new MigrationId(UUID.randomUUID());
    }

    public UUID getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MigrationId that = (MigrationId) o;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "MigrationId{" + value + "}";
    }
}
