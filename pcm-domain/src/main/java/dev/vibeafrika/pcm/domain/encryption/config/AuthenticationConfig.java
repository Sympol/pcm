package dev.vibeafrika.pcm.domain.encryption.config;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Authentication configuration for connecting to a KMS provider.
 *
 * <p>The {@code type} field identifies the authentication mechanism
 * (e.g. {@code "IAM_ROLE"}, {@code "SERVICE_ACCOUNT"}, {@code "CLIENT_CERTIFICATE"},
 * {@code "TOKEN"}). The {@code properties} map carries provider-specific
 * key/value pairs (e.g. role ARN, service-account email, token path).
 */
public final class AuthenticationConfig {

    private final String type;
    private final Map<String, String> properties;

    private AuthenticationConfig(Builder builder) {
        this.type = Objects.requireNonNull(builder.type, "type cannot be null");
        this.properties = builder.properties != null
                ? Map.copyOf(builder.properties)
                : Map.of();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Authentication mechanism type identifier. */
    public String getType() {
        return type;
    }

    /** Provider-specific authentication properties. Never {@code null}; may be empty. */
    public Map<String, String> getProperties() {
        return properties;
    }

    /** Convenience accessor for a single property value. */
    public Optional<String> getProperty(String key) {
        return Optional.ofNullable(properties.get(key));
    }

    public static final class Builder {
        private String type;
        private Map<String, String> properties;

        private Builder() {}

        public Builder type(String type) {
            this.type = type;
            return this;
        }

        public Builder properties(Map<String, String> properties) {
            this.properties = properties;
            return this;
        }

        public AuthenticationConfig build() {
            return new AuthenticationConfig(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationConfig that = (AuthenticationConfig) o;
        return Objects.equals(type, that.type) &&
                Objects.equals(properties, that.properties);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, properties);
    }

    @Override
    public String toString() {
        return "AuthenticationConfig{type='" + type + "', properties=" + properties + '}';
    }
}
