package dev.vibeafrika.pcm.domain.encryption.config;

import java.util.List;
import java.util.Objects;

/**
 * Network-level security configuration for KMS connectivity.
 *
 * <p>Controls mutual TLS enforcement, private-subnet restrictions,
 * IP allow-listing, and circuit-breaker behaviour.
 */
public final class NetworkConfiguration {

    private final boolean mtls;
    private final boolean privateSubnetOnly;
    private final List<String> allowedServiceIPs;
    private final CircuitBreakerConfig circuitBreaker;

    private NetworkConfiguration(Builder builder) {
        this.mtls = builder.mtls;
        this.privateSubnetOnly = builder.privateSubnetOnly;
        this.allowedServiceIPs = builder.allowedServiceIPs != null
                ? List.copyOf(builder.allowedServiceIPs)
                : List.of();
        this.circuitBreaker = Objects.requireNonNull(builder.circuitBreaker, "circuitBreaker cannot be null");
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Whether mutual TLS is required for all KMS connections. */
    public boolean isMtls() {
        return mtls;
    }

    /** Whether KMS access is restricted to private subnets only. */
    public boolean isPrivateSubnetOnly() {
        return privateSubnetOnly;
    }

    /** IP addresses of services permitted to access the KMS. Never {@code null}; may be empty. */
    public List<String> getAllowedServiceIPs() {
        return allowedServiceIPs;
    }

    public CircuitBreakerConfig getCircuitBreaker() {
        return circuitBreaker;
    }

    public static final class Builder {
        private boolean mtls = true;
        private boolean privateSubnetOnly = true;
        private List<String> allowedServiceIPs;
        private CircuitBreakerConfig circuitBreaker;

        private Builder() {}

        public Builder mtls(boolean mtls) {
            this.mtls = mtls;
            return this;
        }

        public Builder privateSubnetOnly(boolean privateSubnetOnly) {
            this.privateSubnetOnly = privateSubnetOnly;
            return this;
        }

        public Builder allowedServiceIPs(List<String> allowedServiceIPs) {
            this.allowedServiceIPs = allowedServiceIPs;
            return this;
        }

        public Builder circuitBreaker(CircuitBreakerConfig circuitBreaker) {
            this.circuitBreaker = circuitBreaker;
            return this;
        }

        public NetworkConfiguration build() {
            return new NetworkConfiguration(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NetworkConfiguration that = (NetworkConfiguration) o;
        return mtls == that.mtls &&
                privateSubnetOnly == that.privateSubnetOnly &&
                Objects.equals(allowedServiceIPs, that.allowedServiceIPs) &&
                Objects.equals(circuitBreaker, that.circuitBreaker);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mtls, privateSubnetOnly, allowedServiceIPs, circuitBreaker);
    }

    @Override
    public String toString() {
        return "NetworkConfiguration{" +
                "mtls=" + mtls +
                ", privateSubnetOnly=" + privateSubnetOnly +
                ", allowedServiceIPs=" + allowedServiceIPs +
                ", circuitBreaker=" + circuitBreaker +
                '}';
    }
}
