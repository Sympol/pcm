package dev.vibeafrika.pcm.profile.domain.model;

import io.github.sympol.pure.asserts.Assert;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Handle value object - represents a unique user handle.
 * Handles must be 3-30 characters, lowercase alphanumeric and underscores only.
 */
public final class Handle {
    private static final Pattern VALID_HANDLE = Pattern.compile("^[a-z0-9_]{3,30}$");
    private static final String ANONYMIZED_PREFIX = "deleted_";
    
    private final String value;

    private Handle(String value, boolean skipValidation) {
        if (skipValidation) {
            this.value = value;
        } else {
            this.value = Assert.field("handle", value)
                .notBlank()
                .minLength(3)
                .maxLength(30)
                .matches(VALID_HANDLE, "Handle must be lowercase alphanumeric with underscores")
                .value();
        }
    }

    /**
     * Create a Handle from a string value.
     * 
     * @param value The handle value (3-30 chars, lowercase alphanumeric + underscore)
     * @return A validated Handle instance
     */
    public static Handle of(String value) {
        return new Handle(value, false);
    }

    /**
     * Create an anonymized handle for GDPR erasure.
     * 
     * @return An anonymized Handle
     */
    public static Handle anonymized() {
        String anonymizedValue = ANONYMIZED_PREFIX + UUID.randomUUID().toString().substring(0, 8);
        return new Handle(anonymizedValue, true);
    }

    /**
     * Check if this handle is anonymized.
     * 
     * @return true if anonymized, false otherwise
     */
    public boolean isAnonymized() {
        return value.startsWith(ANONYMIZED_PREFIX);
    }

    /**
     * Get the handle value.
     * 
     * @return The handle string
     */
    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Handle)) return false;
        Handle handle = (Handle) o;
        return value.equals(handle.value);
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
