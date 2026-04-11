package dev.vibeafrika.pcm.domain.encryption.config;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * Configuration for a Key Management System (KMS) provider.
 *
 * <p>Supports AWS KMS, Azure Key Vault, GCP Cloud KMS, HashiCorp Vault, and
 * on-premise HSM. An optional {@link #failover()} configuration enables
 * automatic failover to a secondary KMS when the primary is unavailable.
 */
public final class KMSConfiguration {

    private final KmsProvider provider;
    private final String endpoint;
    private final String region;
    private final AuthenticationConfig authentication;
    private final FipsLevel certification;
    private final Duration healthCheckInterval;
    private final KMSConfiguration failover;

    private KMSConfiguration(Builder builder) {
        this.provider = Objects.requireNonNull(builder.provider, "provider cannot be null");
        this.endpoint = Objects.requireNonNull(builder.endpoint, "endpoint cannot be null");
        this.region = builder.region;
        this.authentication = Objects.requireNonNull(builder.authentication, "authentication cannot be null");
        this.certification = Objects.requireNonNull(builder.certification, "certification cannot be null");
        this.healthCheckInterval = Objects.requireNonNull(builder.healthCheckInterval, "healthCheckInterval cannot be null");
        this.failover = builder.failover;
    }

    public static Builder builder() {
        return new Builder();
    }

    public KmsProvider getProvider() {
        return provider;
    }

    public String getEndpoint() {
        return endpoint;
    }

    /** Optional region identifier (e.g. AWS region, GCP region). */
    public Optional<String> getRegion() {
        return Optional.ofNullable(region);
    }

    public AuthenticationConfig getAuthentication() {
        return authentication;
    }

    public FipsLevel getCertification() {
        return certification;
    }

    public Duration getHealthCheckInterval() {
        return healthCheckInterval;
    }

    /** Optional failover KMS configuration. */
    public Optional<KMSConfiguration> getFailover() {
        return Optional.ofNullable(failover);
    }

    public static final class Builder {
        private KmsProvider provider;
        private String endpoint;
        private String region;
        private AuthenticationConfig authentication;
        private FipsLevel certification;
        private Duration healthCheckInterval;
        private KMSConfiguration failover;

        private Builder() {}

        public Builder provider(KmsProvider provider) {
            this.provider = provider;
            return this;
        }

        public Builder endpoint(String endpoint) {
            this.endpoint = endpoint;
            return this;
        }

        public Builder region(String region) {
            this.region = region;
            return this;
        }

        public Builder authentication(AuthenticationConfig authentication) {
            this.authentication = authentication;
            return this;
        }

        public Builder certification(FipsLevel certification) {
            this.certification = certification;
            return this;
        }

        public Builder healthCheckInterval(Duration healthCheckInterval) {
            this.healthCheckInterval = healthCheckInterval;
            return this;
        }

        public Builder failover(KMSConfiguration failover) {
            this.failover = failover;
            return this;
        }

        public KMSConfiguration build() {
            return new KMSConfiguration(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KMSConfiguration that = (KMSConfiguration) o;
        return provider == that.provider &&
                Objects.equals(endpoint, that.endpoint) &&
                Objects.equals(region, that.region) &&
                Objects.equals(authentication, that.authentication) &&
                certification == that.certification &&
                Objects.equals(healthCheckInterval, that.healthCheckInterval) &&
                Objects.equals(failover, that.failover);
    }

    @Override
    public int hashCode() {
        return Objects.hash(provider, endpoint, region, authentication, certification,
                healthCheckInterval, failover);
    }

    @Override
    public String toString() {
        return "KMSConfiguration{" +
                "provider=" + provider +
                ", endpoint='" + endpoint + '\'' +
                ", region=" + region +
                ", certification=" + certification +
                ", healthCheckInterval=" + healthCheckInterval +
                ", failover=" + (failover != null ? "<present>" : "<absent>") +
                '}';
    }
}
