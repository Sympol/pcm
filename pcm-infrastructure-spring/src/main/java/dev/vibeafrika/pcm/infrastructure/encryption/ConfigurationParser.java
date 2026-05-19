package dev.vibeafrika.pcm.infrastructure.encryption;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.vibeafrika.pcm.domain.encryption.ConfigurationError;
import dev.vibeafrika.pcm.domain.encryption.EncryptionAlgorithm;
import dev.vibeafrika.pcm.domain.encryption.Result;
import dev.vibeafrika.pcm.domain.encryption.config.*;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.time.Duration;
import java.util.*;

/**
 * Parses YAML or JSON configuration files into {@link EncryptionConfiguration}.
 *
 * <p>Supports two input formats:
 * <ul>
 *   <li>YAML – parsed via SnakeYAML then mapped through Jackson.</li>
 *   <li>JSON – parsed directly via Jackson {@link ObjectMapper}.</li>
 * </ul>
 *
 * <p>Validation performed:
 * <ul>
 *   <li>Encryption algorithm must be one of the supported values.</li>
 *   <li>KMS provider must be one of the supported values.</li>
 *   <li>KMS endpoint must be non-null and non-blank.</li>
 *   <li>KMS certification must be one of the supported FIPS levels.</li>
 * </ul>
 *
 * <p>Returns a {@link ConfigurationError} with a descriptive message on any
 * validation or parsing failure.
 */
public class ConfigurationParser {

    private final ObjectMapper jsonMapper;

    public ConfigurationParser() {
        this.jsonMapper = new ObjectMapper();
        // Register JSR-310 (java.time) module if available on classpath
        jsonMapper.findAndRegisterModules();
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Parses a YAML string into an {@link EncryptionConfiguration}.
     *
     * @param yaml YAML content to parse
     * @return success with parsed configuration, or failure with descriptive error
     */
    public Result<EncryptionConfiguration, ConfigurationError> parseYaml(String yaml) {
        if (yaml == null || yaml.isBlank()) {
            return Result.failure(ConfigurationError.of(
                    "EMPTY_INPUT", "YAML configuration content must not be null or blank"));
        }
        try {
            Map<String, Object> rawMap = loadYaml(yaml);
            String json = jsonMapper.writeValueAsString(rawMap);
            return parseJsonNode(jsonMapper.readTree(json));
        } catch (Exception e) {
            return Result.failure(ConfigurationError.of(
                    "YAML_PARSE_ERROR",
                    "Failed to parse YAML configuration: " + e.getMessage(), e));
        }
    }

    /**
     * Parses a JSON string into an {@link EncryptionConfiguration}.
     *
     * @param json JSON content to parse
     * @return success with parsed configuration, or failure with descriptive error
     */
    public Result<EncryptionConfiguration, ConfigurationError> parseJson(String json) {
        if (json == null || json.isBlank()) {
            return Result.failure(ConfigurationError.of(
                    "EMPTY_INPUT", "JSON configuration content must not be null or blank"));
        }
        try {
            return parseJsonNode(jsonMapper.readTree(json));
        } catch (JsonProcessingException e) {
            return Result.failure(ConfigurationError.of(
                    "JSON_PARSE_ERROR",
                    "Failed to parse JSON configuration: " + e.getMessage(), e));
        }
    }

    /**
     * Parses an {@link InputStream} containing either YAML or JSON.
     * The format is detected automatically: if the first non-whitespace character
     * is '{' the content is treated as JSON, otherwise as YAML.
     *
     * @param inputStream stream to read from
     * @return success with parsed configuration, or failure with descriptive error
     */
    public Result<EncryptionConfiguration, ConfigurationError> parse(InputStream inputStream) {
        if (inputStream == null) {
            return Result.failure(ConfigurationError.of(
                    "NULL_INPUT", "InputStream must not be null"));
        }
        try {
            String content = new String(inputStream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            return parseAutoDetect(content);
        } catch (IOException e) {
            return Result.failure(ConfigurationError.of(
                    "IO_ERROR",
                    "Failed to read configuration stream: " + e.getMessage(), e));
        }
    }

    /**
     * Parses a string that may be either YAML or JSON.
     * Format is auto-detected: JSON if the trimmed content starts with '{'.
     */
    public Result<EncryptionConfiguration, ConfigurationError> parseAutoDetect(String content) {
        if (content == null || content.isBlank()) {
            return Result.failure(ConfigurationError.of(
                    "EMPTY_INPUT", "Configuration content must not be null or blank"));
        }
        if (content.stripLeading().startsWith("{")) {
            return parseJson(content);
        }
        return parseYaml(content);
    }

    // -------------------------------------------------------------------------
    // Internal parsing
    // -------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private Map<String, Object> loadYaml(String yaml) {
        Yaml snakeYaml = new Yaml();
        Object loaded = snakeYaml.load(new StringReader(yaml));
        if (loaded instanceof Map) {
            return (Map<String, Object>) loaded;
        }
        throw new IllegalArgumentException(
                "YAML root element must be a mapping, got: "
                        + (loaded == null ? "null" : loaded.getClass().getSimpleName()));
    }

    private Result<EncryptionConfiguration, ConfigurationError> parseJsonNode(JsonNode root) {
        List<String> errors = new ArrayList<>();

        // --- kms ---
        JsonNode kmsNode = root.path("kms");
        if (kmsNode.isMissingNode()) {
            errors.add("'kms' section is required");
        }

        // --- encryption ---
        JsonNode encNode = root.path("encryption");
        if (encNode.isMissingNode()) {
            errors.add("'encryption' section is required");
        }

        if (!errors.isEmpty()) {
            return Result.failure(ConfigurationError.of(
                    "MISSING_REQUIRED_SECTIONS",
                    "Configuration is missing required sections: " + String.join(", ", errors)));
        }

        // Parse each section, collecting errors
        Result<KMSConfiguration, ConfigurationError> kmsResult = parseKmsConfiguration(kmsNode);
        if (kmsResult.isFailure()) {
            return Result.failure(kmsResult.getError().orElseThrow());
        }

        Result<EncryptionSettings, ConfigurationError> encResult = parseEncryptionSettings(encNode);
        if (encResult.isFailure()) {
            return Result.failure(encResult.getError().orElseThrow());
        }

        KeyRotationPolicy keyRotation = parseKeyRotationPolicy(root.path("keyRotation"));
        CachingPolicy caching = parseCachingPolicy(root.path("caching"));
        AuditConfigurationModel audit = parseAuditConfiguration(root.path("audit"));
        NetworkConfiguration network = parseNetworkConfiguration(root.path("network"));

        EncryptionConfiguration config = EncryptionConfiguration.builder()
                .kms(kmsResult.getValue().orElseThrow())
                .encryption(encResult.getValue().orElseThrow())
                .keyRotation(keyRotation)
                .caching(caching)
                .audit(audit)
                .network(network)
                .build();

        return Result.success(config);
    }

    // -------------------------------------------------------------------------
    // KMS Configuration
    // -------------------------------------------------------------------------

    private Result<KMSConfiguration, ConfigurationError> parseKmsConfiguration(JsonNode node) {
        // provider
        String providerStr = textOrNull(node, "provider");
        if (providerStr == null) {
            return Result.failure(ConfigurationError.of(
                    "INVALID_KMS_PARAMETERS",
                    "'kms.provider' is required. Supported values: "
                            + Arrays.toString(KmsProvider.values())));
        }
        KmsProvider provider;
        try {
            provider = KmsProvider.valueOf(providerStr.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return Result.failure(ConfigurationError.of(
                    "INVALID_KMS_PARAMETERS",
                    "Unsupported KMS provider '" + providerStr + "'. Supported values: "
                            + Arrays.toString(KmsProvider.values())));
        }

        // endpoint
        String endpoint = textOrNull(node, "endpoint");
        if (endpoint == null || endpoint.isBlank()) {
            return Result.failure(ConfigurationError.of(
                    "INVALID_KMS_PARAMETERS",
                    "'kms.endpoint' is required and must not be blank"));
        }

        // certification
        String certStr = textOrNull(node, "certification");
        if (certStr == null) {
            return Result.failure(ConfigurationError.of(
                    "INVALID_KMS_PARAMETERS",
                    "'kms.certification' is required. Supported values: "
                            + Arrays.toString(FipsLevel.values())));
        }
        FipsLevel certification;
        try {
            certification = FipsLevel.valueOf(certStr.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return Result.failure(ConfigurationError.of(
                    "INVALID_KMS_PARAMETERS",
                    "Unsupported FIPS certification level '" + certStr + "'. Supported values: "
                            + Arrays.toString(FipsLevel.values())));
        }

        // region (optional)
        String region = textOrNull(node, "region");

        // healthCheckInterval (optional, default 30s)
        Duration healthCheckInterval = parseDuration(node, "healthCheckInterval", Duration.ofSeconds(30));

        // authentication
        JsonNode authNode = node.path("authentication");
        AuthenticationConfig authentication = parseAuthenticationConfig(authNode);

        // failover (optional, recursive)
        KMSConfiguration failover = null;
        JsonNode failoverNode = node.path("failover");
        if (!failoverNode.isMissingNode() && !failoverNode.isNull()) {
            Result<KMSConfiguration, ConfigurationError> failoverResult = parseKmsConfiguration(failoverNode);
            if (failoverResult.isFailure()) {
                return Result.failure(ConfigurationError.of(
                        "INVALID_KMS_PARAMETERS",
                        "Invalid failover KMS configuration: "
                                + failoverResult.getError().orElseThrow().getMessage()));
            }
            failover = failoverResult.getValue().orElseThrow();
        }

        KMSConfiguration.Builder builder = KMSConfiguration.builder()
                .provider(provider)
                .endpoint(endpoint)
                .certification(certification)
                .healthCheckInterval(healthCheckInterval)
                .authentication(authentication);

        if (region != null) {
            builder.region(region);
        }
        if (failover != null) {
            builder.failover(failover);
        }

        return Result.success(builder.build());
    }

    private AuthenticationConfig parseAuthenticationConfig(JsonNode node) {
        if (node.isMissingNode() || node.isNull()) {
            // Default: empty authentication config
            return AuthenticationConfig.builder().type("NONE").build();
        }
        String type = textOrDefault(node, "type", "NONE");
        Map<String, String> properties = new LinkedHashMap<>();
        JsonNode propsNode = node.path("properties");
        if (!propsNode.isMissingNode() && propsNode.isObject()) {
            propsNode.fields().forEachRemaining(entry ->
                    properties.put(entry.getKey(), entry.getValue().asText()));
        }
        return AuthenticationConfig.builder()
                .type(type)
                .properties(properties)
                .build();
    }

    // -------------------------------------------------------------------------
    // Encryption Settings
    // -------------------------------------------------------------------------

    private Result<EncryptionSettings, ConfigurationError> parseEncryptionSettings(JsonNode node) {
        // defaultAlgorithm
        String algorithmStr = textOrNull(node, "defaultAlgorithm");
        if (algorithmStr == null) {
            return Result.failure(ConfigurationError.of(
                    "INVALID_ALGORITHM",
                    "'encryption.defaultAlgorithm' is required. Supported values: "
                            + Arrays.toString(EncryptionAlgorithm.values())));
        }
        EncryptionAlgorithm algorithm;
        try {
            algorithm = EncryptionAlgorithm.valueOf(algorithmStr.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return Result.failure(ConfigurationError.of(
                    "INVALID_ALGORITHM",
                    "Unsupported encryption algorithm '" + algorithmStr
                            + "'. Supported values: " + Arrays.toString(EncryptionAlgorithm.values())));
        }

        // ivGeneration (optional, default COUNTER_BASED)
        String ivGenStr = textOrDefault(node, "ivGeneration", IvGenerationStrategy.COUNTER_BASED.name());
        IvGenerationStrategy ivGeneration;
        try {
            ivGeneration = IvGenerationStrategy.valueOf(ivGenStr.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return Result.failure(ConfigurationError.of(
                    "INVALID_ALGORITHM",
                    "Unsupported IV generation strategy '" + ivGenStr
                            + "'. Supported values: " + Arrays.toString(IvGenerationStrategy.values())));
        }

        // counterPersistenceInterval (optional, default 1000)
        int counterPersistenceInterval = intOrDefault(node, "counterPersistenceInterval",
                EncryptionSettings.DEFAULT_COUNTER_PERSISTENCE_INTERVAL);
        if (counterPersistenceInterval < 1) {
            return Result.failure(ConfigurationError.of(
                    "INVALID_ALGORITHM",
                    "'encryption.counterPersistenceInterval' must be >= 1, got: "
                            + counterPersistenceInterval));
        }

        return Result.success(EncryptionSettings.builder()
                .defaultAlgorithm(algorithm)
                .ivGeneration(ivGeneration)
                .counterPersistenceInterval(counterPersistenceInterval)
                .build());
    }

    // -------------------------------------------------------------------------
    // Key Rotation Policy
    // -------------------------------------------------------------------------

    private KeyRotationPolicy parseKeyRotationPolicy(JsonNode node) {
        if (node.isMissingNode() || node.isNull()) {
            return KeyRotationPolicy.defaults();
        }
        return KeyRotationPolicy.builder()
                .dekRotationDays(intOrDefault(node, "dekRotationDays",
                        KeyRotationPolicy.DEFAULT_DEK_ROTATION_DAYS))
                .dekRotationBytes(longOrDefault(node, "dekRotationBytes",
                        KeyRotationPolicy.DEFAULT_DEK_ROTATION_BYTES))
                .dekRotationOperations(longOrDefault(node, "dekRotationOperations",
                        KeyRotationPolicy.DEFAULT_DEK_ROTATION_OPERATIONS))
                .kekRotationDays(intOrDefault(node, "kekRotationDays",
                        KeyRotationPolicy.DEFAULT_KEK_ROTATION_DAYS))
                .emergencyRotationTimeMinutes(intOrDefault(node, "emergencyRotationTimeMinutes",
                        KeyRotationPolicy.DEFAULT_EMERGENCY_ROTATION_TIME_MINUTES))
                .build();
    }

    // -------------------------------------------------------------------------
    // Caching Policy
    // -------------------------------------------------------------------------

    private CachingPolicy parseCachingPolicy(JsonNode node) {
        if (node.isMissingNode() || node.isNull()) {
            return CachingPolicy.defaults();
        }
        Duration ttl = parseDuration(node, "dekCacheTTL", CachingPolicy.DEFAULT_DEK_CACHE_TTL);
        int maxSize = intOrDefault(node, "dekCacheMaxSize", CachingPolicy.DEFAULT_DEK_CACHE_MAX_SIZE);
        boolean secureMemory = boolOrDefault(node, "secureMemory", false);

        String evictionStr = textOrDefault(node, "evictionPolicy", EvictionPolicy.LRU.name());
        EvictionPolicy evictionPolicy;
        try {
            evictionPolicy = EvictionPolicy.valueOf(evictionStr.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            evictionPolicy = EvictionPolicy.LRU;
        }

        return CachingPolicy.builder()
                .dekCacheTTL(ttl)
                .dekCacheMaxSize(maxSize)
                .evictionPolicy(evictionPolicy)
                .secureMemory(secureMemory)
                .build();
    }

    // -------------------------------------------------------------------------
    // Audit Configuration
    // -------------------------------------------------------------------------

    private AuditConfigurationModel parseAuditConfiguration(JsonNode node) {
        if (node.isMissingNode() || node.isNull()) {
            return AuditConfigurationModel.builder().build();
        }
        String levelStr = textOrDefault(node, "level", AuditLevel.HIGH.name());
        AuditLevel level;
        try {
            level = AuditLevel.valueOf(levelStr.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            level = AuditLevel.HIGH;
        }

        int retentionDays = intOrDefault(node, "retentionDays",
                AuditConfigurationModel.DEFAULT_RETENTION_DAYS);
        boolean encryptLogs = boolOrDefault(node, "encryptLogs", true);
        boolean signLogs = boolOrDefault(node, "signLogs", true);

        AuditConfigurationModel.Builder builder = AuditConfigurationModel.builder()
                .level(level)
                .retentionDays(retentionDays)
                .encryptLogs(encryptLogs)
                .signLogs(signLogs);

        JsonNode samplingNode = node.path("samplingRate");
        if (!samplingNode.isMissingNode() && !samplingNode.isNull()) {
            builder.samplingRate(samplingNode.asDouble());
        }

        return builder.build();
    }

    // -------------------------------------------------------------------------
    // Network Configuration
    // -------------------------------------------------------------------------

    private NetworkConfiguration parseNetworkConfiguration(JsonNode node) {
        if (node.isMissingNode() || node.isNull()) {
            return NetworkConfiguration.builder()
                    .circuitBreaker(new CircuitBreakerConfig(5, 60, 3))
                    .build();
        }
        boolean mtls = boolOrDefault(node, "mtls", true);
        boolean privateSubnetOnly = boolOrDefault(node, "privateSubnetOnly", true);

        List<String> allowedIPs = new ArrayList<>();
        JsonNode ipsNode = node.path("allowedServiceIPs");
        if (!ipsNode.isMissingNode() && ipsNode.isArray()) {
            ipsNode.forEach(ip -> allowedIPs.add(ip.asText()));
        }

        CircuitBreakerConfig circuitBreaker = parseCircuitBreakerConfig(node.path("circuitBreaker"));

        return NetworkConfiguration.builder()
                .mtls(mtls)
                .privateSubnetOnly(privateSubnetOnly)
                .allowedServiceIPs(allowedIPs)
                .circuitBreaker(circuitBreaker)
                .build();
    }

    private CircuitBreakerConfig parseCircuitBreakerConfig(JsonNode node) {
        if (node.isMissingNode() || node.isNull()) {
            return new CircuitBreakerConfig(5, 60, 3);
        }
        int failureThreshold = intOrDefault(node, "failureThreshold", 5);
        int recoveryTimeSeconds = intOrDefault(node, "recoveryTimeSeconds", 60);
        int halfOpenMaxCalls = intOrDefault(node, "halfOpenMaxCalls", 3);
        return new CircuitBreakerConfig(failureThreshold, recoveryTimeSeconds, halfOpenMaxCalls);
    }

    // -------------------------------------------------------------------------
    // Utility helpers
    // -------------------------------------------------------------------------

    private String textOrNull(JsonNode node, String field) {
        JsonNode child = node.path(field);
        if (child.isMissingNode() || child.isNull()) return null;
        String text = child.asText(null);
        return (text == null || text.isBlank()) ? null : text;
    }

    private String textOrDefault(JsonNode node, String field, String defaultValue) {
        String value = textOrNull(node, field);
        return value != null ? value : defaultValue;
    }

    private int intOrDefault(JsonNode node, String field, int defaultValue) {
        JsonNode child = node.path(field);
        if (child.isMissingNode() || child.isNull()) return defaultValue;
        return child.asInt(defaultValue);
    }

    private long longOrDefault(JsonNode node, String field, long defaultValue) {
        JsonNode child = node.path(field);
        if (child.isMissingNode() || child.isNull()) return defaultValue;
        return child.asLong(defaultValue);
    }

    private boolean boolOrDefault(JsonNode node, String field, boolean defaultValue) {
        JsonNode child = node.path(field);
        if (child.isMissingNode() || child.isNull()) return defaultValue;
        return child.asBoolean(defaultValue);
    }

    /**
     * Parses a duration field. Accepts ISO-8601 strings (e.g. "PT30S") or
     * plain integer seconds.
     */
    private Duration parseDuration(JsonNode node, String field, Duration defaultValue) {
        JsonNode child = node.path(field);
        if (child.isMissingNode() || child.isNull()) return defaultValue;
        if (child.isNumber()) {
            return Duration.ofSeconds(child.asLong());
        }
        String text = child.asText(null);
        if (text == null || text.isBlank()) return defaultValue;
        try {
            return Duration.parse(text);
        } catch (Exception e) {
            return defaultValue;
        }
    }
}
