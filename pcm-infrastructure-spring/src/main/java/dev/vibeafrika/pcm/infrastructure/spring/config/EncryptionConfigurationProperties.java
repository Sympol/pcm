package dev.vibeafrika.pcm.infrastructure.spring.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Type-safe configuration properties for the PCM encryption subsystem.
 *
 * <p>Bound from the {@code pcm.encryption} prefix in application configuration files.
 *
 * <p>Example YAML:
 * <pre>
 * pcm:
 *   encryption:
 *     environment: PROD
 *     kms:
 *       provider: AWS_KMS
 *       endpoint: https://kms.us-east-1.amazonaws.com
 *       region: us-east-1
 *     dek-cache:
 *       max-size: 1000
 *       ttl-minutes: 60
 *     key-rotation:
 *       dek-rotation-days: 90
 *       kek-rotation-days: 365
 *     audit:
 *       level: HIGH
 *       encrypt-logs: true
 *       sign-logs: true
 *     network:
 *       mtls-enabled: true
 *       private-subnet-only: true
 * </pre>
 *
 */
@ConfigurationProperties(prefix = "pcm.encryption")
public class EncryptionConfigurationProperties {

    /** Deployment environment: DEV, STAGING, or PROD. Defaults to DEV. */
    private String environment = "DEV";

    /** Default bounded context for encryption operations. Defaults to PROFILE. */
    private String defaultContext = "PROFILE";

    /** Blind index global salt (must be overridden in production). */
    private String blindIndexGlobalSalt = "default-dev-salt-change-in-prod";

    private final Kms kms = new Kms();
    private final DekCache dekCache = new DekCache();
    private final KeyRotation keyRotation = new KeyRotation();
    private final Audit audit = new Audit();
    private final Network network = new Network();

    // -------------------------------------------------------------------------
    // Getters / Setters
    // -------------------------------------------------------------------------

    public String getEnvironment() { return environment; }
    public void setEnvironment(String environment) { this.environment = environment; }

    public String getDefaultContext() { return defaultContext; }
    public void setDefaultContext(String defaultContext) { this.defaultContext = defaultContext; }

    public String getBlindIndexGlobalSalt() { return blindIndexGlobalSalt; }
    public void setBlindIndexGlobalSalt(String blindIndexGlobalSalt) { this.blindIndexGlobalSalt = blindIndexGlobalSalt; }

    public Kms getKms() { return kms; }
    public DekCache getDekCache() { return dekCache; }
    public KeyRotation getKeyRotation() { return keyRotation; }
    public Audit getAudit() { return audit; }
    public Network getNetwork() { return network; }

    // =========================================================================
    // Nested configuration classes
    // =========================================================================

    /**
     * KMS connection parameters.
     */
    public static class Kms {

        /**
         * KMS provider: AWS_KMS, AZURE_KEY_VAULT, GCP_KMS, VAULT.
         * Required for production deployments.
         */
        private String provider;

        /** KMS endpoint URL. Required. */
        private String endpoint;

        /** Cloud region (e.g., us-east-1 for AWS). Optional. */
        private String region;

        /** GCP project ID. Required when provider=GCP_KMS. */
        private String gcpProjectId;

        /** GCP location ID (e.g., us-east1). Required when provider=GCP_KMS. */
        private String gcpLocationId;

        /** FIPS certification level: FIPS_140_2_L2, FIPS_140_2_L3. Defaults to FIPS_140_2_L2. */
        private String certification = "FIPS_140_2_L2";

        /** KMS health check interval. Defaults to 30 seconds. */
        private Duration healthCheckInterval = Duration.ofSeconds(30);

        private final Mtls mtls = new Mtls();
        private final Failover failover = new Failover();

        public String getProvider() { return provider; }
        public void setProvider(String provider) { this.provider = provider; }

        public String getEndpoint() { return endpoint; }
        public void setEndpoint(String endpoint) { this.endpoint = endpoint; }

        public String getRegion() { return region; }
        public void setRegion(String region) { this.region = region; }

        public String getGcpProjectId() { return gcpProjectId; }
        public void setGcpProjectId(String gcpProjectId) { this.gcpProjectId = gcpProjectId; }

        public String getGcpLocationId() { return gcpLocationId; }
        public void setGcpLocationId(String gcpLocationId) { this.gcpLocationId = gcpLocationId; }

        public String getCertification() { return certification; }
        public void setCertification(String certification) { this.certification = certification; }

        public Duration getHealthCheckInterval() { return healthCheckInterval; }
        public void setHealthCheckInterval(Duration healthCheckInterval) { this.healthCheckInterval = healthCheckInterval; }

        public Mtls getMtls() { return mtls; }
        public Failover getFailover() { return failover; }

        /** mTLS configuration for KMS communication. */
        public static class Mtls {
            private boolean enabled = false;
            private String keystorePath;
            private String keystorePassword;
            private String truststorePath;
            private String truststorePassword;

            public boolean isEnabled() { return enabled; }
            public void setEnabled(boolean enabled) { this.enabled = enabled; }

            public String getKeystorePath() { return keystorePath; }
            public void setKeystorePath(String keystorePath) { this.keystorePath = keystorePath; }

            public String getKeystorePassword() { return keystorePassword; }
            public void setKeystorePassword(String keystorePassword) { this.keystorePassword = keystorePassword; }

            public String getTruststorePath() { return truststorePath; }
            public void setTruststorePath(String truststorePath) { this.truststorePath = truststorePath; }

            public String getTruststorePassword() { return truststorePassword; }
            public void setTruststorePassword(String truststorePassword) { this.truststorePassword = truststorePassword; }
        }

        /** Failover KMS configuration. */
        public static class Failover {
            private boolean enabled = false;
            private String provider;
            private String endpoint;
            private String region;

            public boolean isEnabled() { return enabled; }
            public void setEnabled(boolean enabled) { this.enabled = enabled; }

            public String getProvider() { return provider; }
            public void setProvider(String provider) { this.provider = provider; }

            public String getEndpoint() { return endpoint; }
            public void setEndpoint(String endpoint) { this.endpoint = endpoint; }

            public String getRegion() { return region; }
            public void setRegion(String region) { this.region = region; }
        }
    }

    /**
     * DEK cache configuration.
     */
    public static class DekCache {
        /** Maximum number of DEKs to hold in the LRU cache. Defaults to 1000. */
        private int maxSize = 1000;

        /** Time-to-live for cached DEKs in minutes. Defaults to 60. */
        private int ttlMinutes = 60;

        /** Whether to use secure memory allocation for cached DEKs. */
        private boolean secureMemory = false;

        public int getMaxSize() { return maxSize; }
        public void setMaxSize(int maxSize) { this.maxSize = maxSize; }

        public int getTtlMinutes() { return ttlMinutes; }
        public void setTtlMinutes(int ttlMinutes) { this.ttlMinutes = ttlMinutes; }

        public boolean isSecureMemory() { return secureMemory; }
        public void setSecureMemory(boolean secureMemory) { this.secureMemory = secureMemory; }
    }

    /**
     * Key rotation policy configuration.
     */
    public static class KeyRotation {
        /** DEK rotation interval in days. Defaults to 90. */
        private int dekRotationDays = 90;

        /** DEK rotation threshold in bytes (1 TB). */
        private long dekRotationBytes = 1_099_511_627_776L;

        /** DEK rotation threshold in operations (2^32). */
        private long dekRotationOperations = 4_294_967_296L;

        /** KEK rotation interval in days. Defaults to 365. */
        private int kekRotationDays = 365;

        /** Emergency rotation time limit in minutes. Defaults to 15. */
        private int emergencyRotationTimeMinutes = 15;

        public int getDekRotationDays() { return dekRotationDays; }
        public void setDekRotationDays(int dekRotationDays) { this.dekRotationDays = dekRotationDays; }

        public long getDekRotationBytes() { return dekRotationBytes; }
        public void setDekRotationBytes(long dekRotationBytes) { this.dekRotationBytes = dekRotationBytes; }

        public long getDekRotationOperations() { return dekRotationOperations; }
        public void setDekRotationOperations(long dekRotationOperations) { this.dekRotationOperations = dekRotationOperations; }

        public int getKekRotationDays() { return kekRotationDays; }
        public void setKekRotationDays(int kekRotationDays) { this.kekRotationDays = kekRotationDays; }

        public int getEmergencyRotationTimeMinutes() { return emergencyRotationTimeMinutes; }
        public void setEmergencyRotationTimeMinutes(int emergencyRotationTimeMinutes) {
            this.emergencyRotationTimeMinutes = emergencyRotationTimeMinutes;
        }
    }

    /**
     * Audit logging configuration.
     */
    public static class Audit {
        /** Minimum audit log level: CRITICAL, HIGH, MEDIUM, LOW. Defaults to HIGH. */
        private String level = "HIGH";

        /** Audit log retention in days. Defaults to 365 (1 year). */
        private int retentionDays = 365;

        /** Whether to encrypt audit logs at rest. Defaults to true. */
        private boolean encryptLogs = true;

        /** Whether to sign audit log entries with HMAC. Defaults to true. */
        private boolean signLogs = true;

        /** Sampling rate for high-volume operations (1 = log all). Defaults to 1. */
        private int samplingRate = 1;

        public String getLevel() { return level; }
        public void setLevel(String level) { this.level = level; }

        public int getRetentionDays() { return retentionDays; }
        public void setRetentionDays(int retentionDays) { this.retentionDays = retentionDays; }

        public boolean isEncryptLogs() { return encryptLogs; }
        public void setEncryptLogs(boolean encryptLogs) { this.encryptLogs = encryptLogs; }

        public boolean isSignLogs() { return signLogs; }
        public void setSignLogs(boolean signLogs) { this.signLogs = signLogs; }

        public int getSamplingRate() { return samplingRate; }
        public void setSamplingRate(int samplingRate) { this.samplingRate = samplingRate; }
    }

    /**
     * Network security configuration.
     */
    public static class Network {
        /** Whether to enforce mTLS for KMS communication. Defaults to false (dev). */
        private boolean mtlsEnabled = false;

        /** Whether to restrict KMS access to private subnets only. Defaults to false (dev). */
        private boolean privateSubnetOnly = false;

        /** Allowed service IP addresses for KMS access. */
        private List<String> allowedServiceIps = new ArrayList<>();

        private final CircuitBreaker circuitBreaker = new CircuitBreaker();

        public boolean isMtlsEnabled() { return mtlsEnabled; }
        public void setMtlsEnabled(boolean mtlsEnabled) { this.mtlsEnabled = mtlsEnabled; }

        public boolean isPrivateSubnetOnly() { return privateSubnetOnly; }
        public void setPrivateSubnetOnly(boolean privateSubnetOnly) { this.privateSubnetOnly = privateSubnetOnly; }

        public List<String> getAllowedServiceIps() { return allowedServiceIps; }
        public void setAllowedServiceIps(List<String> allowedServiceIps) { this.allowedServiceIps = allowedServiceIps; }

        public CircuitBreaker getCircuitBreaker() { return circuitBreaker; }

        /** Circuit breaker configuration for KMS availability. */
        public static class CircuitBreaker {
            /** Number of failures before opening the circuit. Defaults to 5. */
            private int failureThreshold = 5;

            /** Recovery time in seconds before attempting half-open. Defaults to 60. */
            private int recoveryTimeSeconds = 60;

            /** Maximum calls in half-open state. Defaults to 3. */
            private int halfOpenMaxCalls = 3;

            public int getFailureThreshold() { return failureThreshold; }
            public void setFailureThreshold(int failureThreshold) { this.failureThreshold = failureThreshold; }

            public int getRecoveryTimeSeconds() { return recoveryTimeSeconds; }
            public void setRecoveryTimeSeconds(int recoveryTimeSeconds) { this.recoveryTimeSeconds = recoveryTimeSeconds; }

            public int getHalfOpenMaxCalls() { return halfOpenMaxCalls; }
            public void setHalfOpenMaxCalls(int halfOpenMaxCalls) { this.halfOpenMaxCalls = halfOpenMaxCalls; }
        }
    }
}
