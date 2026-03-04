package dev.vibeafrika.pcm.segment.domain.model;

import io.github.sympol.pure.asserts.Assert;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * SegmentName value object - represents a segment name with validation.
 */
public final class SegmentName {
    private static final Pattern VALID_NAME = Pattern.compile("^[a-zA-Z0-9_\\-\\s]{3,100}$");
    private final String value;

    private SegmentName(String value) {
        this.value = Assert.field("segmentName", value)
            .notBlank()
            .minLength(3)
            .maxLength(100)
            .matches(VALID_NAME, "Segment name must be 3-100 characters, alphanumeric with spaces, hyphens and underscores")
            .value();
    }

    public static SegmentName of(String value) {
        return new SegmentName(value);
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SegmentName)) return false;
        SegmentName that = (SegmentName) o;
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
