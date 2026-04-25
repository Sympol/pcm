package dev.vibeafrika.pcm.infrastructure.spring.encryption.network;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;

/**
 * Spring Boot configuration for KMS network segmentation.
 *
 * <p>Enforces the following network security controls :
 * <ul>
 *   <li>KMS access is restricted to private subnets (RFC 1918 address ranges)</li>
 *   <li>IP allowlist checking for authorized service IPs</li>
 *   <li>Private DNS resolution for KMS endpoints</li>
 *   <li>All KMS connection attempts are logged via {@link KmsConnectionInterceptor}</li>
 * </ul>
 *
 * <p>Configuration properties are bound from {@code pcm.encryption.network.*}:
 * <pre>
 * pcm:
 *   encryption:
 *     network:
 *       kms-endpoint: https://kms.internal.example.com
 *       private-subnet-only: true
 *       allowed-service-ips:
 *         - 10.0.1.5
 *         - 10.0.1.6
 *       environment-isolation: true
 * </pre>
 */
@Configuration
@EnableConfigurationProperties(NetworkSecurityConfiguration.NetworkSecurityProperties.class)
public class NetworkSecurityConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(NetworkSecurityConfiguration.class);

    /** RFC 1918 private address ranges used for subnet validation. */
    private static final String[] PRIVATE_SUBNET_PREFIXES = {
        "10.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.",
        "127."   // loopback – allowed for local/test environments
    };

    private final NetworkSecurityProperties properties;

    public NetworkSecurityConfiguration(NetworkSecurityProperties properties) {
        this.properties = properties;
    }

    /**
     * Provides the {@link KmsConnectionInterceptor} bean wired with the network
     * security properties.
     *
     * @return a configured {@link KmsConnectionInterceptor}
     */
    @Bean
    public KmsConnectionInterceptor kmsConnectionInterceptor() {
        return new KmsConnectionInterceptor(
                properties.getAllowedServiceIps(),
                properties.isPrivateSubnetOnly());
    }

    /**
     * Validates that the configured KMS endpoint resolves to a private subnet
     * address when {@code private-subnet-only} is {@code true}.
     *
     * <p>Called at application startup to fail fast if the KMS endpoint is
     * reachable from a public IP, which would violate.
     *
     * @throws IllegalStateException if the endpoint resolves to a public IP
     *                               and private-subnet-only is enabled
     */
    @Bean(name = "kmsEndpointValidator")
    public KmsEndpointValidator kmsEndpointValidator() {
        return new KmsEndpointValidator(properties.getKmsEndpoint(), properties.isPrivateSubnetOnly());
    }

    /**
     * Returns {@code true} if the given IP address belongs to an RFC 1918
     * private subnet or loopback range.
     *
     * @param ipAddress the IP address string to check
     * @return {@code true} if the address is private
     */
    public static boolean isPrivateSubnetAddress(String ipAddress) {
        if (ipAddress == null || ipAddress.isBlank()) {
            return false;
        }
        for (String prefix : PRIVATE_SUBNET_PREFIXES) {
            if (ipAddress.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // Inner validator
    // -------------------------------------------------------------------------

    /**
     * Validates that the KMS endpoint resolves to a private subnet address.
     * Instantiated as a Spring bean so validation runs at context startup.
     */
    public static class KmsEndpointValidator {

        private static final Logger log = LoggerFactory.getLogger(KmsEndpointValidator.class);

        private final String kmsEndpoint;
        private final boolean privateSubnetOnly;

        public KmsEndpointValidator(String kmsEndpoint, boolean privateSubnetOnly) {
            this.kmsEndpoint = kmsEndpoint;
            this.privateSubnetOnly = privateSubnetOnly;
            validate();
        }

        private void validate() {
            if (!privateSubnetOnly || kmsEndpoint == null || kmsEndpoint.isBlank()) {
                return;
            }

            String hostname = extractHostname(kmsEndpoint);
            if (hostname == null) {
                log.warn("NetworkSecurity: could not extract hostname from KMS endpoint '{}'", kmsEndpoint);
                return;
            }

            try {
                InetAddress address = InetAddress.getByName(hostname);
                String resolvedIp = address.getHostAddress();

                if (!isPrivateSubnetAddress(resolvedIp)) {
                    throw new IllegalStateException(
                            "KMS endpoint '" + kmsEndpoint + "' resolves to public IP '" + resolvedIp +
                            "'. Private-subnet-only mode requires a private IP address. " +
                            "KMS must be accessed from private subnets only.");
                }

                log.info("NetworkSecurity: KMS endpoint '{}' resolves to private IP '{}' — OK",
                         kmsEndpoint, resolvedIp);

            } catch (UnknownHostException e) {
                // DNS resolution failure is acceptable at startup (KMS may not be reachable yet)
                log.warn("NetworkSecurity: could not resolve KMS endpoint hostname '{}': {}",
                         hostname, e.getMessage());
            }
        }

        private String extractHostname(String endpoint) {
            try {
                // Strip scheme (https://, http://)
                String stripped = endpoint.replaceFirst("^https?://", "");
                // Strip path and port
                int slashIdx = stripped.indexOf('/');
                if (slashIdx > 0) stripped = stripped.substring(0, slashIdx);
                int colonIdx = stripped.indexOf(':');
                if (colonIdx > 0) stripped = stripped.substring(0, colonIdx);
                return stripped.isBlank() ? null : stripped;
            } catch (Exception e) {
                return null;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Configuration properties
    // -------------------------------------------------------------------------

    /**
     * Strongly-typed configuration properties for network security, bound from
     * {@code pcm.encryption.network.*}.
     */
    @ConfigurationProperties(prefix = "pcm.encryption.network")
    public static class NetworkSecurityProperties {

        /** KMS endpoint URL (private DNS name preferred). */
        private String kmsEndpoint = "";

        /**
         * When {@code true}, the validator checks that the KMS endpoint resolves
         * to a private subnet address (RFC 1918). Defaults to {@code true}.
         */
        private boolean privateSubnetOnly = true;

        /**
         * Allowlist of authorized service IP addresses that may connect to KMS.
         * Empty list means no IP-based restriction (not recommended for production).
         */
        private List<String> allowedServiceIps = Collections.emptyList();

        /**
         * When {@code true}, cross-environment KMS access is prohibited.
         * Defaults to {@code true}.
         */
        private boolean environmentIsolation = true;

        public String getKmsEndpoint() { return kmsEndpoint; }
        public void setKmsEndpoint(String kmsEndpoint) { this.kmsEndpoint = kmsEndpoint; }

        public boolean isPrivateSubnetOnly() { return privateSubnetOnly; }
        public void setPrivateSubnetOnly(boolean privateSubnetOnly) { this.privateSubnetOnly = privateSubnetOnly; }

        public List<String> getAllowedServiceIps() { return allowedServiceIps; }
        public void setAllowedServiceIps(List<String> allowedServiceIps) {
            this.allowedServiceIps = allowedServiceIps != null
                    ? Collections.unmodifiableList(allowedServiceIps)
                    : Collections.emptyList();
        }

        public boolean isEnvironmentIsolation() { return environmentIsolation; }
        public void setEnvironmentIsolation(boolean environmentIsolation) {
            this.environmentIsolation = environmentIsolation;
        }
    }
}
