package dev.vibeafrika.pcm.infrastructure.encryption.kms;

import dev.vibeafrika.pcm.domain.encryption.BoundedContext;
import dev.vibeafrika.pcm.domain.encryption.DEK;
import dev.vibeafrika.pcm.domain.encryption.EncryptedDEK;
import dev.vibeafrika.pcm.domain.encryption.Environment;
import dev.vibeafrika.pcm.domain.encryption.IKMSClient;
import dev.vibeafrika.pcm.domain.encryption.KMSError;
import dev.vibeafrika.pcm.domain.encryption.KMSHealth;
import dev.vibeafrika.pcm.domain.encryption.Result;
import dev.vibeafrika.pcm.domain.encryption.Unit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * HashiCorp Vault implementation of {@link IKMSClient} using the Transit secrets engine.
 *
 * <p>The Transit engine acts as an "encryption as a service" — KEKs are stored and
 * managed inside Vault and never leave its secure boundary. Only ciphertext is
 * returned to the application, matching the envelope encryption model.
 *
 * <p>Key naming convention in Vault Transit:
 * <pre>
 *   pcm/{environment}/{bounded_context}/{kekId}
 *   e.g. pcm/dev/profile/3f2a1b4c-...
 * </pre>
 *
 * <p>Activated when {@code pcm.encryption.kms.provider=VAULT}.
 *
 * <p>Required Vault setup (done once at bootstrap or via Vault policy):
 * <pre>
 *   vault secrets enable transit
 *   vault write -f transit/keys/pcm-bootstrap  # health-check key
 * </pre>
 *
 * <p>Required environment variables:
 * <ul>
 *   <li>{@code VAULT_ADDR} — Vault server address (e.g. {@code http://vault:8200})</li>
 *   <li>{@code VAULT_TOKEN} — Vault token with transit read/write/encrypt/decrypt policy</li>
 * </ul>
 */
@Component
@ConditionalOnProperty(name = "pcm.encryption.kms.provider", havingValue = "VAULT")
public class VaultKmsClient implements IKMSClient {

    private static final Logger logger = LoggerFactory.getLogger(VaultKmsClient.class);

    /** Transit engine mount path. */
    private static final String TRANSIT_PATH = "transit";

    /** Key used for health checks — must exist in Vault Transit. */
    private static final String HEALTH_CHECK_KEY = "pcm-bootstrap";

    /** KV v2 mount path for secret storage. */
    private static final String SECRET_PATH = "secret/data/pcm";

    private final VaultTemplate vaultTemplate;

    public VaultKmsClient(VaultTemplate vaultTemplate) {
        this.vaultTemplate = Objects.requireNonNull(vaultTemplate, "VaultTemplate cannot be null");
        logger.info("VaultKmsClient initialised — using Vault Transit engine at path '{}'", TRANSIT_PATH);
    }

    // -------------------------------------------------------------------------
    // DEK envelope encryption
    // -------------------------------------------------------------------------

    /**
     * Encrypts a DEK using the Vault Transit key identified by {@code kekId}.
     *
     * <p>The DEK bytes are Base64-encoded and sent to Vault's
     * {@code transit/encrypt/{keyName}} endpoint. Vault returns a ciphertext
     * in the form {@code vault:v1:<base64>} which is stored as the encrypted DEK.
     *
     * @param dek   the plaintext DEK to encrypt
     * @param kekId the UUID of the Vault Transit key to use as KEK
     * @return the encrypted DEK, or a {@link KMSError} on failure
     */
    @Override
    public Result<EncryptedDEK, KMSError> encryptDEK(DEK dek, UUID kekId) {
        String keyName = transitKeyName(kekId);
        try {
            String plaintext = Base64.getEncoder().encodeToString(dek.getKeyMaterial());
            Map<String, Object> request = Map.of("plaintext", plaintext);

            VaultResponse response = vaultTemplate.write(
                    TRANSIT_PATH + "/encrypt/" + keyName, request);

            if (response == null || response.getData() == null) {
                return Result.failure(KMSError.of("VAULT_ENCRYPT_NULL_RESPONSE",
                        "Vault returned null response for encrypt operation on key: " + keyName));
            }

            String ciphertext = (String) response.getData().get("ciphertext");
            if (ciphertext == null || ciphertext.isBlank()) {
                return Result.failure(KMSError.of("VAULT_ENCRYPT_NO_CIPHERTEXT",
                        "Vault response missing ciphertext for key: " + keyName));
            }

            // Store the Vault ciphertext string as UTF-8 bytes in EncryptedDEK
            byte[] ciphertextBytes = ciphertext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            return Result.success(EncryptedDEK.of(ciphertextBytes, kekId, "VAULT_TRANSIT"));

        } catch (Exception e) {
            logger.error("Vault DEK encryption failed for key {}: {}", keyName, e.getMessage());
            return Result.failure(KMSError.of("VAULT_ENCRYPT_FAILED",
                    "DEK encryption failed for key '" + keyName + "': " + e.getMessage(), e));
        }
    }

    /**
     * Decrypts an encrypted DEK using the Vault Transit key identified by {@code kekId}.
     *
     * <p>The stored ciphertext (Vault format {@code vault:v1:<base64>}) is sent to
     * {@code transit/decrypt/{keyName}}. Vault returns the original plaintext DEK bytes.
     *
     * @param encryptedDEK the encrypted DEK produced by {@link #encryptDEK}
     * @param kekId        the UUID of the Vault Transit key used during encryption
     * @return the decrypted DEK, or a {@link KMSError} on failure
     */
    @Override
    public Result<DEK, KMSError> decryptDEK(EncryptedDEK encryptedDEK, UUID kekId) {
        String keyName = transitKeyName(kekId);
        try {
            // Recover the Vault ciphertext string from the stored bytes
            String ciphertext = new String(encryptedDEK.getCiphertext(), java.nio.charset.StandardCharsets.UTF_8);
            Map<String, Object> request = Map.of("ciphertext", ciphertext);

            VaultResponse response = vaultTemplate.write(
                    TRANSIT_PATH + "/decrypt/" + keyName, request);

            if (response == null || response.getData() == null) {
                return Result.failure(KMSError.of("VAULT_DECRYPT_NULL_RESPONSE",
                        "Vault returned null response for decrypt operation on key: " + keyName));
            }

            String plaintext = (String) response.getData().get("plaintext");
            if (plaintext == null || plaintext.isBlank()) {
                return Result.failure(KMSError.of("VAULT_DECRYPT_NO_PLAINTEXT",
                        "Vault response missing plaintext for key: " + keyName));
            }

            byte[] dekBytes = Base64.getDecoder().decode(plaintext);
            return Result.success(DEK.of(dekBytes));

        } catch (Exception e) {
            logger.error("Vault DEK decryption failed for key {}: {}", keyName, e.getMessage());
            return Result.failure(KMSError.of("VAULT_DECRYPT_FAILED",
                    "DEK decryption failed for key '" + keyName + "': " + e.getMessage(), e));
        }
    }

    // -------------------------------------------------------------------------
    // KEK lifecycle
    // -------------------------------------------------------------------------

    /**
     * Generates a new KEK in Vault Transit for the given bounded context and environment.
     *
     * <p>Creates a new AES-256-GCM Transit key. The key material never leaves Vault.
     * Returns the UUID that will be used as the key name in subsequent encrypt/decrypt calls.
     *
     * @param context     the bounded context (PROFILE, CONSENT, SEGMENT, PREFERENCE)
     * @param environment the deployment environment (DEV, STAGING, PROD)
     * @return the new KEK UUID, or a {@link KMSError} on failure
     */
    @Override
    public Result<UUID, KMSError> generateKEK(BoundedContext context, Environment environment) {
        UUID kekId = UUID.randomUUID();
        String keyName = transitKeyName(kekId);
        try {
            // Create a new AES-256-GCM key in Vault Transit
            Map<String, Object> request = Map.of(
                    "type", "aes256-gcm96",
                    "exportable", false,
                    "allow_plaintext_backup", false
            );
            vaultTemplate.write(TRANSIT_PATH + "/keys/" + keyName, request);
            logger.info("Generated Vault Transit KEK '{}' for context={} env={}", keyName, context, environment);
            return Result.success(kekId);

        } catch (Exception e) {
            logger.error("Vault KEK generation failed for key {}: {}", keyName, e.getMessage());
            return Result.failure(KMSError.of("VAULT_GENERATE_KEK_FAILED",
                    "KEK generation failed for key '" + keyName + "': " + e.getMessage(), e));
        }
    }

    /**
     * Deletes a DEK key from Vault Transit, making all data encrypted with it
     * permanently unrecoverable (cryptographic erasure for GDPR Art. 17).
     *
     * <p>Vault requires the key to have {@code deletion_allowed=true} before it
     * can be deleted. This method sets that flag then deletes the key.
     *
     * @param keyId the UUID of the DEK key to delete
     * @return success, or a {@link KMSError} on failure
     */
    @Override
    public Result<Unit, KMSError> deleteDEK(UUID keyId) {
        String keyName = transitKeyName(keyId);
        try {
            // First allow deletion, then delete
            vaultTemplate.write(TRANSIT_PATH + "/keys/" + keyName + "/config",
                    Map.of("deletion_allowed", true));
            vaultTemplate.delete(TRANSIT_PATH + "/keys/" + keyName);
            logger.info("Deleted Vault Transit key '{}' (cryptographic erasure)", keyName);
            return Result.success(Unit.unit());

        } catch (Exception e) {
            logger.error("Vault DEK deletion failed for key {}: {}", keyName, e.getMessage());
            return Result.failure(KMSError.of("VAULT_DELETE_DEK_FAILED",
                    "DEK deletion failed for key '" + keyName + "': " + e.getMessage(), e));
        }
    }

    // -------------------------------------------------------------------------
    // Secret management (KV v2)
    // -------------------------------------------------------------------------

    /**
     * Stores a secret in Vault KV v2 at {@code secret/data/pcm/{secretId}}.
     *
     * @param secretId    unique identifier for the secret
     * @param secretValue the plaintext secret value
     * @param kekId       unused for Vault (Vault manages its own encryption at rest)
     * @return success, or a {@link KMSError} on failure
     */
    @Override
    public Result<Unit, KMSError> storeSecret(UUID secretId, String secretValue, UUID kekId) {
        String path = SECRET_PATH + "/" + secretId;
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("value", secretValue);
            vaultTemplate.write(path, Map.of("data", data));
            logger.debug("Stored secret {} in Vault KV", secretId);
            return Result.success(Unit.unit());

        } catch (Exception e) {
            logger.error("Vault secret storage failed for {}: {}", secretId, e.getMessage());
            return Result.failure(KMSError.of("VAULT_STORE_SECRET_FAILED",
                    "Secret storage failed for id '" + secretId + "': " + e.getMessage(), e));
        }
    }

    /**
     * Retrieves a secret from Vault KV v2.
     *
     * @param secretId the unique identifier of the secret
     * @param kekId    unused for Vault
     * @return the plaintext secret value, or a {@link KMSError} on failure
     */
    @Override
    @SuppressWarnings("unchecked")
    public Result<String, KMSError> retrieveSecret(UUID secretId, UUID kekId) {
        String path = SECRET_PATH + "/" + secretId;
        try {
            VaultResponse response = vaultTemplate.read(path);
            if (response == null || response.getData() == null) {
                return Result.failure(KMSError.of("VAULT_SECRET_NOT_FOUND",
                        "Secret not found in Vault: " + secretId));
            }

            // KV v2 wraps the actual data under a "data" key
            Object dataObj = response.getData().get("data");
            if (dataObj instanceof Map<?, ?> dataMap) {
                Object value = dataMap.get("value");
                if (value instanceof String str) {
                    return Result.success(str);
                }
            }

            return Result.failure(KMSError.of("VAULT_SECRET_INVALID_FORMAT",
                    "Secret value missing or not a string for id: " + secretId));

        } catch (Exception e) {
            logger.error("Vault secret retrieval failed for {}: {}", secretId, e.getMessage());
            return Result.failure(KMSError.of("VAULT_RETRIEVE_SECRET_FAILED",
                    "Secret retrieval failed for id '" + secretId + "': " + e.getMessage(), e));
        }
    }

    /**
     * Deletes a secret from Vault KV v2.
     *
     * @param secretId the unique identifier of the secret to delete
     * @return success, or a {@link KMSError} on failure
     */
    @Override
    public Result<Unit, KMSError> deleteSecret(UUID secretId) {
        String path = SECRET_PATH + "/" + secretId;
        try {
            vaultTemplate.delete(path);
            logger.debug("Deleted secret {} from Vault KV", secretId);
            return Result.success(Unit.unit());

        } catch (Exception e) {
            logger.error("Vault secret deletion failed for {}: {}", secretId, e.getMessage());
            return Result.failure(KMSError.of("VAULT_DELETE_SECRET_FAILED",
                    "Secret deletion failed for id '" + secretId + "': " + e.getMessage(), e));
        }
    }

    // -------------------------------------------------------------------------
    // Health check
    // -------------------------------------------------------------------------

    /**
     * Checks Vault availability by reading the health-check Transit key metadata.
     *
     * <p>The {@code pcm-bootstrap} key must exist in Vault Transit. It is created
     * once during initial Vault setup:
     * <pre>
     *   vault write -f transit/keys/pcm-bootstrap
     * </pre>
     *
     * @return healthy status with latency, or unhealthy on any error
     */
    @Override
    public Result<KMSHealth, KMSError> healthCheck() {
        long start = System.currentTimeMillis();
        try {
            VaultResponse response = vaultTemplate.read(TRANSIT_PATH + "/keys/" + HEALTH_CHECK_KEY);
            long latency = System.currentTimeMillis() - start;

            if (response != null && response.getData() != null) {
                return Result.success(KMSHealth.healthy(latency));
            }
            return Result.success(KMSHealth.degraded(latency,
                    "Vault health-check key '" + HEALTH_CHECK_KEY + "' not found — run bootstrap"));

        } catch (Exception e) {
            logger.warn("Vault health check failed: {}", e.getMessage());
            return Result.success(KMSHealth.unhealthy("Vault unreachable: " + e.getMessage()));
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Derives the Vault Transit key name from a KEK UUID.
     *
     * <p>Vault key names must match {@code [a-zA-Z0-9_-]+}, so we use the UUID
     * string directly (hyphens are allowed).
     *
     * @param kekId the KEK UUID
     * @return the Vault Transit key name
     */
    private static String transitKeyName(UUID kekId) {
        return "pcm-" + kekId.toString();
    }
}
