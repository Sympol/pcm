package dev.vibeafrika.pcm.segment.domain.model;

import io.github.sympol.pure.asserts.Assert;
import java.util.Objects;
import java.util.UUID;

/**
 * SegmentId value object - wraps UUID with domain meaning.
 */
public final class SegmentId {
    private final UUID value;

    private SegmentId(UUID value) {
        this.value = Assert.field("segmentId", value)
            .notNull()
            .value();
    }

    public static SegmentId of(UUID value) {
        return new SegmentId(value);
    }

    public static SegmentId generate() {
        return new SegmentId(UUID.randomUUID());
    }

    public UUID getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SegmentId)) return false;
        SegmentId that = (SegmentId) o;
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
