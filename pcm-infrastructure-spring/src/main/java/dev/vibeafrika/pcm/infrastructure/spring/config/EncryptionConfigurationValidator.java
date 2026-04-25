package dev.vibeafrika.pcm.infrastructure.spring.config;

import dev.vibeafrika.pcm.domain.encryption.BoundedContext;
import dev.vibeafrika.pcm.domain.encryption.Environment;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Validates the encryption configuration on application startup.
 *
 * <p>Performs fail-fast validation of all required encryption settings,
 * preventing the application from starting with an invalid configuration.
 * This implements the "fail fast with descriptive errors" principle from 
 * requirements
 *
 * <p>Validation rules:
 * <ul>
 *   <li>Environment must be a valid {@link Environment} value (DEV, STAGING, PROD)</li>
 *   <li>Default context must be a valid {@link BoundedContext} value</li>
 *   <li>KMS provider must be one of the supported values</li>
 *   <li>KMS endpoint must be non-blank</li>
 *   <li>DEK cache max-size must be positive</li>
 *   <li>DEK cache TTL must be positive</li>
 *   <li>Key rotation days must be positive</li>
 *   <li>Audit level must be a valid value</li>
 *   <li>In PROD environment, blind index salt must not be the default dev value</li>
 *   <li>In PROD environment, mTLS should be enabled (warning)</li>
 * </ul>
 *
 */
@Component
public class EncryptionConfigurationValidator {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionConfigurationValidator.class);

    private static final String DEFAULT_DEV_SALT = "default-dev-salt-change-in-prod";

    private static final Set<String> VALID_KMS_PROVIDERS =
            Set.of("AWS_KMS", "AZURE_KEY_VAULT", "GCP_KMS", "VAULT");

    private static final Set<String> VALID_AUDIT_LEVELS =
            Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW");

    private static final Set<String> VALID_FIPS_LEVELS =
            Set.of("FIPS_140_2_L2", "FIPS_140_2_L3");

    private final EncryptionConfigurationProperties properties;

    public EncryptionConfigurationValidator(EncryptionConfigurationProperties properties) {
        this.properties = properties;
    }

    /**
     * Validates the encryption configuration at application startup.
     *
     * <p>Collects all validation errors and throws a single
     * {@link IllegalStateException} with a descriptive message listing all
     * problems found, rather than failing on the first error.
     *
     * @throws IllegalStateException if any configuration is invalid
     */
    @PostConstruct
    public void validate() {
        logger.info("Validating encryption configuration...");
        List<String> errors = new ArrayList<>();

        validateEnvironment(errors);
        validateDefaultContext(errors);
        validateKmsConfiguration(errors);
        validateDekCacheConfiguration(errors);
        validateKeyRotationConfiguration(errors);
        validateAuditConfiguration(errors);
        validateProductionConstraints(errors);

        if (!errors.isEmpty()) {
            String message = buildErrorMessage(errors);
            logger.error("Encryption configuration validation failed:\n{}", message);
            throw new IllegalStateException(message);
        }

        logger.info("Encryption configuration validated successfully. Environment={}, KMS provider={}",
                properties.getEnvironment(),
                properties.getKms().getProvider() != null ? properties.getKms().getProvider() : "not configured");
    }

    // -------------------------------------------------------------------------
    // Validation methods
    // -------------------------------------------------------------------------

    private void validateEnvironment(List<String> errors) {
        String env = properties.getEnvironment();
        if (env == null || env.isBlank()) {
            errors.add("pcm.encryption.environment is required. Valid values: DEV, STAGING, PROD");
            return;
        }
        try {
            Environment.valueOf(env.toUpperCase());
        } catch (IllegalArgumentException e) {
            errors.add("pcm.encryption.environment '" + env + "' is invalid. Valid values: DEV, STAGING, PROD");
        }
    }

    private void validateDefaultContext(List<String> errors) {
        String ctx = properties.getDefaultContext();
        if (ctx == null || ctx.isBlank()) {
            errors.add("pcm.encryption.default-context is required. Valid values: "
                    + java.util.Arrays.toString(BoundedContext.values()));
            return;
        }
        try {
            BoundedContext.valueOf(ctx.toUpperCase());
        } catch (IllegalArgumentException e) {
            errors.add("pcm.encryption.default-context '" + ctx + "' is invalid. Valid values: "
                    + java.util.Arrays.toString(BoundedContext.values()));
        }
    }

    private void validateKmsConfiguration(List<String> errors) {
        EncryptionConfigurationProperties.Kms kms = properties.getKms();

        // Provider is required only when a KMS client bean is expected to be wired.
        // If not set, the application can still start (e.g., for testing with mocks).
        if (kms.getProvider() != null && !kms.getProvider().isBlank()) {
            String provider = kms.getProvider().toUpperCase();
            if (!VALID_KMS_PROVIDERS.contains(provider)) {
                errors.add("pcm.encryption.kms.provider '" + kms.getProvider()
                        + "' is invalid. Valid values: " + VALID_KMS_PROVIDERS);
            }

            // Endpoint is required when provider is set
            if (kms.getEndpoint() == null || kms.getEndpoint().isBlank()) {
                errors.add("pcm.encryption.kms.endpoint is required when kms.provider is set");
            }

            // GCP-specific validation
            if ("GCP_KMS".equals(provider)) {
                if (kms.getGcpProjectId() == null || kms.getGcpProjectId().isBlank()) {
                    errors.add("pcm.encryption.kms.gcp-project-id is required when kms.provider=GCP_KMS");
                }
                if (kms.getGcpLocationId() == null || kms.getGcpLocationId().isBlank()) {
                    errors.add("pcm.encryption.kms.gcp-location-id is required when kms.provider=GCP_KMS");
                }
            }

            // AWS-specific validation
            if ("AWS_KMS".equals(provider)) {
                if (kms.getRegion() == null || kms.getRegion().isBlank()) {
                    errors.add("pcm.encryption.kms.region is required when kms.provider=AWS_KMS");
                }
            }

            // Certification level validation
            if (kms.getCertification() != null && !kms.getCertification().isBlank()) {
                if (!VALID_FIPS_LEVELS.contains(kms.getCertification().toUpperCase())) {
                    errors.add("pcm.encryption.kms.certification '" + kms.getCertification()
                            + "' is invalid. Valid values: " + VALID_FIPS_LEVELS);
                }
            }

            // mTLS validation: if enabled, keystore and truststore paths are required
            EncryptionConfigurationProperties.Kms.Mtls mtls = kms.getMtls();
            if (mtls.isEnabled()) {
                if (mtls.getKeystorePath() == null || mtls.getKeystorePath().isBlank()) {
                    errors.add("pcm.encryption.kms.mtls.keystore-path is required when mtls is enabled");
                }
                if (mtls.getTruststorePath() == null || mtls.getTruststorePath().isBlank()) {
                    errors.add("pcm.encryption.kms.mtls.truststore-path is required when mtls is enabled");
                }
            }
        }
    }

    private void validateDekCacheConfiguration(List<String> errors) {
        EncryptionConfigurationProperties.DekCache cache = properties.getDekCache();

        if (cache.getMaxSize() <= 0) {
            errors.add("pcm.encryption.dek-cache.max-size must be > 0, got: " + cache.getMaxSize());
        }
        if (cache.getMaxSize() > 10_000) {
            logger.warn("pcm.encryption.dek-cache.max-size={} is unusually large; consider reducing to <= 1000",
                    cache.getMaxSize());
        }
        if (cache.getTtlMinutes() <= 0) {
            errors.add("pcm.encryption.dek-cache.ttl-minutes must be > 0, got: " + cache.getTtlMinutes());
        }
        if (cache.getTtlMinutes() > 1440) {
            logger.warn("pcm.encryption.dek-cache.ttl-minutes={} exceeds 24 hours; "
                    + "requirement 10.5 specifies maximum TTL of 1 hour", cache.getTtlMinutes());
        }
    }

    private void validateKeyRotationConfiguration(List<String> errors) {
        EncryptionConfigurationProperties.KeyRotation rotation = properties.getKeyRotation();

        if (rotation.getDekRotationDays() <= 0) {
            errors.add("pcm.encryption.key-rotation.dek-rotation-days must be > 0, got: "
                    + rotation.getDekRotationDays());
        }
        if (rotation.getDekRotationDays() > 90) {
            logger.warn("pcm.encryption.key-rotation.dek-rotation-days={} exceeds the recommended 90-day maximum",
                    rotation.getDekRotationDays());
        }
        if (rotation.getKekRotationDays() <= 0) {
            errors.add("pcm.encryption.key-rotation.kek-rotation-days must be > 0, got: "
                    + rotation.getKekRotationDays());
        }
        if (rotation.getEmergencyRotationTimeMinutes() <= 0) {
            errors.add("pcm.encryption.key-rotation.emergency-rotation-time-minutes must be > 0, got: "
                    + rotation.getEmergencyRotationTimeMinutes());
        }
        if (rotation.getDekRotationBytes() <= 0) {
            errors.add("pcm.encryption.key-rotation.dek-rotation-bytes must be > 0, got: "
                    + rotation.getDekRotationBytes());
        }
        if (rotation.getDekRotationOperations() <= 0) {
            errors.add("pcm.encryption.key-rotation.dek-rotation-operations must be > 0, got: "
                    + rotation.getDekRotationOperations());
        }
    }

    private void validateAuditConfiguration(List<String> errors) {
        EncryptionConfigurationProperties.Audit audit = properties.getAudit();

        if (audit.getLevel() == null || audit.getLevel().isBlank()) {
            errors.add("pcm.encryption.audit.level is required. Valid values: " + VALID_AUDIT_LEVELS);
            return;
        }
        if (!VALID_AUDIT_LEVELS.contains(audit.getLevel().toUpperCase())) {
            errors.add("pcm.encryption.audit.level '" + audit.getLevel()
                    + "' is invalid. Valid values: " + VALID_AUDIT_LEVELS);
        }
        if (audit.getRetentionDays() < 365) {
            logger.warn("pcm.encryption.audit.retention-days={} is below the minimum 365-day requirement (Req 7.11)",
                    audit.getRetentionDays());
        }
        if (audit.getSamplingRate() < 1) {
            errors.add("pcm.encryption.audit.sampling-rate must be >= 1, got: " + audit.getSamplingRate());
        }
    }

    private void validateProductionConstraints(List<String> errors) {
        String env = properties.getEnvironment();
        if (env == null) return;

        boolean isProd = "PROD".equalsIgnoreCase(env);
        boolean isStaging = "STAGING".equalsIgnoreCase(env);

        if (isProd || isStaging) {
            // Blind index salt must not be the default dev value in non-dev environments
            if (DEFAULT_DEV_SALT.equals(properties.getBlindIndexGlobalSalt())) {
                errors.add("pcm.encryption.blind-index-global-salt must be changed from the default dev value "
                        + "in " + env + " environment. Set a strong, unique secret salt.");
            }

            // mTLS should be enabled in production/staging
            if (!properties.getNetwork().isMtlsEnabled()) {
                logger.warn("pcm.encryption.network.mtls-enabled=false in {} environment. "
                        + "mTLS is strongly recommended for KMS communication (Req 27.2)", env);
            }

            // FIPS 140-2 Level 3 required for production
            if (isProd) {
                String cert = properties.getKms().getCertification();
                if (cert != null && "FIPS_140_2_L2".equalsIgnoreCase(cert)) {
                    logger.warn("pcm.encryption.kms.certification=FIPS_140_2_L2 in PROD environment. "
                            + "FIPS 140-2 Level 3 is required for production (Req 18.1)");
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private String buildErrorMessage(List<String> errors) {
        StringBuilder sb = new StringBuilder();
        sb.append("Encryption configuration is invalid. Found ")
          .append(errors.size())
          .append(" error(s):\n");
        for (int i = 0; i < errors.size(); i++) {
            sb.append("  ").append(i + 1).append(". ").append(errors.get(i)).append("\n");
        }
        sb.append("Please review your application.yml under the 'pcm.encryption' prefix.");
        return sb.toString();
    }
}
