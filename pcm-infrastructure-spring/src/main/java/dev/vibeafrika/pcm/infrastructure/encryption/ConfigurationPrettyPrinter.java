package dev.vibeafrika.pcm.infrastructure.encryption;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.vibeafrika.pcm.domain.encryption.ConfigurationError;
import dev.vibeafrika.pcm.domain.encryption.Result;
import dev.vibeafrika.pcm.domain.encryption.config.*;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Formats an {@link EncryptionConfiguration} back into a YAML or JSON string.
 *
 * <p>The output is the inverse of {@link ConfigurationParser}: every field
 * written here uses the same key names that the parser reads, so a round-trip
 * (parse → print → parse) produces an equivalent configuration object.
 *
 * <p>Usage:
 * <pre>{@code
 * ConfigurationPrettyPrinter printer = new ConfigurationPrettyPrinter();
 * String yaml = printer.toYaml(config).getValue().orElseThrow();
 * String json = printer.toJson(config).getValue().orElseThrow();
 * }</pre>
 */
public class ConfigurationPrettyPrinter {

    private final ObjectMapper jsonMapper;

    public ConfigurationPrettyPrinter() {
        this.jsonMapper = new ObjectMapper();
        jsonMapper.findAndRegisterModules();
        jsonMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Formats the configuration as a YAML string.
     *
     * @param config the configuration to format; must not be {@code null}
     * @return success with the YAML string, or failure with a descriptive error
     */
    public Result<String, ConfigurationError> toYaml(EncryptionConfiguration config) {
        if (config == null) {
            return Result.failure(ConfigurationError.of(
                    "NULL_INPUT", "EncryptionConfiguration must not be null"));
        }
        try {
            Map<String, Object> map = toMap(config);
            DumperOptions opts = new DumperOptions();
            opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            opts.setPrettyFlow(true);
            opts.setIndent(2);
            Yaml yaml = new Yaml(opts);
            return Result.success(yaml.dump(map));
        } catch (Exception e) {
            return Result.failure(ConfigurationError.of(
                    "YAML_PRINT_ERROR",
                    "Failed to format configuration as YAML: " + e.getMessage(), e));
        }
    }

    /**
     * Formats the configuration as a pretty-printed JSON string.
     *
     * @param config the configuration to format; must not be {@code null}
     * @return success with the JSON string, or failure with a descriptive error
     */
    public Result<String, ConfigurationError> toJson(EncryptionConfiguration config) {
        if (config == null) {
            return Result.failure(ConfigurationError.of(
                    "NULL_INPUT", "EncryptionConfiguration must not be null"));
        }
        try {
            ObjectNode root = buildJsonNode(config);
            return Result.success(jsonMapper.writeValueAsString(root));
        } catch (JsonProcessingException e) {
            return Result.failure(ConfigurationError.of(
                    "JSON_PRINT_ERROR",
                    "Failed to format configuration as JSON: " + e.getMessage(), e));
        }
    }

    // -------------------------------------------------------------------------
    // JSON node builder
    // -------------------------------------------------------------------------

    private ObjectNode buildJsonNode(EncryptionConfiguration config) {
        ObjectNode root = jsonMapper.createObjectNode();
        root.set("kms", kmsNode(config.getKms()));
        root.set("encryption", encryptionNode(config.getEncryption()));
        root.set("keyRotation", keyRotationNode(config.getKeyRotation()));
        root.set("caching", cachingNode(config.getCaching()));
        root.set("audit", auditNode(config.getAudit()));
        root.set("network", networkNode(config.getNetwork()));
        return root;
    }

    private ObjectNode kmsNode(KMSConfiguration kms) {
        ObjectNode node = jsonMapper.createObjectNode();
        node.put("provider", kms.getProvider().name());
        node.put("endpoint", kms.getEndpoint());
        kms.getRegion().ifPresent(r -> node.put("region", r));
        node.put("certification", kms.getCertification().name());
        node.put("healthCheckInterval", formatDuration(kms.getHealthCheckInterval()));
        node.set("authentication", authNode(kms.getAuthentication()));
        kms.getFailover().ifPresent(f -> node.set("failover", kmsNode(f)));
        return node;
    }

    private ObjectNode authNode(AuthenticationConfig auth) {
        ObjectNode node = jsonMapper.createObjectNode();
        node.put("type", auth.getType());
        if (!auth.getProperties().isEmpty()) {
            ObjectNode props = jsonMapper.createObjectNode();
            auth.getProperties().forEach(props::put);
            node.set("properties", props);
        }
        return node;
    }

    private ObjectNode encryptionNode(EncryptionSettings enc) {
        ObjectNode node = jsonMapper.createObjectNode();
        node.put("defaultAlgorithm", enc.getDefaultAlgorithm().name());
        node.put("ivGeneration", enc.getIvGeneration().name());
        node.put("counterPersistenceInterval", enc.getCounterPersistenceInterval());
        return node;
    }

    private ObjectNode keyRotationNode(KeyRotationPolicy policy) {
        ObjectNode node = jsonMapper.createObjectNode();
        node.put("dekRotationDays", policy.getDekRotationDays());
        node.put("dekRotationBytes", policy.getDekRotationBytes());
        node.put("dekRotationOperations", policy.getDekRotationOperations());
        node.put("kekRotationDays", policy.getKekRotationDays());
        node.put("emergencyRotationTimeMinutes", policy.getEmergencyRotationTimeMinutes());
        return node;
    }

    private ObjectNode cachingNode(CachingPolicy caching) {
        ObjectNode node = jsonMapper.createObjectNode();
        node.put("dekCacheTTL", formatDuration(caching.getDekCacheTTL()));
        node.put("dekCacheMaxSize", caching.getDekCacheMaxSize());
        node.put("evictionPolicy", caching.getEvictionPolicy().name());
        node.put("secureMemory", caching.isSecureMemory());
        return node;
    }

    private ObjectNode auditNode(AuditConfigurationModel audit) {
        ObjectNode node = jsonMapper.createObjectNode();
        node.put("level", audit.getLevel().name());
        node.put("retentionDays", audit.getRetentionDays());
        node.put("encryptLogs", audit.isEncryptLogs());
        node.put("signLogs", audit.isSignLogs());
        audit.getSamplingRate().ifPresent(r -> node.put("samplingRate", r));
        return node;
    }

    private ObjectNode networkNode(NetworkConfiguration network) {
        ObjectNode node = jsonMapper.createObjectNode();
        node.put("mtls", network.isMtls());
        node.put("privateSubnetOnly", network.isPrivateSubnetOnly());
        if (!network.getAllowedServiceIPs().isEmpty()) {
            ArrayNode ips = jsonMapper.createArrayNode();
            network.getAllowedServiceIPs().forEach(ips::add);
            node.set("allowedServiceIPs", ips);
        }
        node.set("circuitBreaker", circuitBreakerNode(network.getCircuitBreaker()));
        return node;
    }

    private ObjectNode circuitBreakerNode(CircuitBreakerConfig cb) {
        ObjectNode node = jsonMapper.createObjectNode();
        node.put("failureThreshold", cb.failureThreshold());
        node.put("recoveryTimeSeconds", cb.recoveryTimeSeconds());
        node.put("halfOpenMaxCalls", cb.halfOpenMaxCalls());
        return node;
    }

    // -------------------------------------------------------------------------
    // Map builder (for YAML serialisation via SnakeYAML)
    // -------------------------------------------------------------------------

    private Map<String, Object> toMap(EncryptionConfiguration config) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("kms", kmsToMap(config.getKms()));
        root.put("encryption", encryptionToMap(config.getEncryption()));
        root.put("keyRotation", keyRotationToMap(config.getKeyRotation()));
        root.put("caching", cachingToMap(config.getCaching()));
        root.put("audit", auditToMap(config.getAudit()));
        root.put("network", networkToMap(config.getNetwork()));
        return root;
    }

    private Map<String, Object> kmsToMap(KMSConfiguration kms) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("provider", kms.getProvider().name());
        map.put("endpoint", kms.getEndpoint());
        kms.getRegion().ifPresent(r -> map.put("region", r));
        map.put("certification", kms.getCertification().name());
        map.put("healthCheckInterval", formatDuration(kms.getHealthCheckInterval()));
        map.put("authentication", authToMap(kms.getAuthentication()));
        kms.getFailover().ifPresent(f -> map.put("failover", kmsToMap(f)));
        return map;
    }

    private Map<String, Object> authToMap(AuthenticationConfig auth) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("type", auth.getType());
        if (!auth.getProperties().isEmpty()) {
            map.put("properties", new LinkedHashMap<>(auth.getProperties()));
        }
        return map;
    }

    private Map<String, Object> encryptionToMap(EncryptionSettings enc) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("defaultAlgorithm", enc.getDefaultAlgorithm().name());
        map.put("ivGeneration", enc.getIvGeneration().name());
        map.put("counterPersistenceInterval", enc.getCounterPersistenceInterval());
        return map;
    }

    private Map<String, Object> keyRotationToMap(KeyRotationPolicy policy) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("dekRotationDays", policy.getDekRotationDays());
        map.put("dekRotationBytes", policy.getDekRotationBytes());
        map.put("dekRotationOperations", policy.getDekRotationOperations());
        map.put("kekRotationDays", policy.getKekRotationDays());
        map.put("emergencyRotationTimeMinutes", policy.getEmergencyRotationTimeMinutes());
        return map;
    }

    private Map<String, Object> cachingToMap(CachingPolicy caching) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("dekCacheTTL", formatDuration(caching.getDekCacheTTL()));
        map.put("dekCacheMaxSize", caching.getDekCacheMaxSize());
        map.put("evictionPolicy", caching.getEvictionPolicy().name());
        map.put("secureMemory", caching.isSecureMemory());
        return map;
    }

    private Map<String, Object> auditToMap(AuditConfigurationModel audit) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("level", audit.getLevel().name());
        map.put("retentionDays", audit.getRetentionDays());
        map.put("encryptLogs", audit.isEncryptLogs());
        map.put("signLogs", audit.isSignLogs());
        audit.getSamplingRate().ifPresent(r -> map.put("samplingRate", r));
        return map;
    }

    private Map<String, Object> networkToMap(NetworkConfiguration network) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("mtls", network.isMtls());
        map.put("privateSubnetOnly", network.isPrivateSubnetOnly());
        if (!network.getAllowedServiceIPs().isEmpty()) {
            map.put("allowedServiceIPs", network.getAllowedServiceIPs());
        }
        map.put("circuitBreaker", circuitBreakerToMap(network.getCircuitBreaker()));
        return map;
    }

    private Map<String, Object> circuitBreakerToMap(CircuitBreakerConfig cb) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("failureThreshold", cb.failureThreshold());
        map.put("recoveryTimeSeconds", cb.recoveryTimeSeconds());
        map.put("halfOpenMaxCalls", cb.halfOpenMaxCalls());
        return map;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Formats a {@link java.time.Duration} as an ISO-8601 string (e.g. {@code "PT1H"}).
     * The parser accepts ISO-8601 strings, so this ensures a clean round-trip.
     */
    private String formatDuration(java.time.Duration duration) {
        return duration.toString(); // java.time.Duration.toString() returns ISO-8601
    }
}
