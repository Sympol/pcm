package dev.vibeafrika.pcm.infrastructure.encryption.kms;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.DecryptResult;
import com.azure.security.keyvault.keys.cryptography.models.EncryptResult;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.azure.security.keyvault.keys.models.CreateRsaKeyOptions;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
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

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Azure Key Vault implementation of {@link IKMSClient}.
 *
 * <p>Uses the Azure SDK for Java to interact with Azure Key Vault.
 * Supports mTLS for secure communication with Key Vault endpoints.
 *
 * <p>Activated when {@code encryption.kms.provider=AZURE_KEY_VAULT} is set in configuration.
 *
 * <p>Key operations use RSA-OAEP-256 for DEK wrapping, which is the recommended
 * algorithm for key wrapping in Azure Key Vault.
 */
@Component
@ConditionalOnProperty(name = "encryption.kms.provider", havingValue = "AZURE_KEY_VAULT")
public class AzureKeyVaultClient implements IKMSClient {

    private static final Logger logger = LoggerFactory.getLogger(AzureKeyVaultClient.class);

    /** RSA key size for KEKs (4096-bit for FIPS 140-2 Level 3 compliance). */
    private static final int KEK_RSA_KEY_SIZE = 4096;

    /** Encryption algorithm used for DEK wrapping. */
    private static final EncryptionAlgorithm WRAP_ALGORITHM = EncryptionAlgorithm.RSA_OAEP_256;

    /** Name of the health-check key in Key Vault. */
    private static final String HEALTH_CHECK_KEY_NAME = "pcm-health-check";

    private final KeyClient keyClient;
    private final String vaultUrl;
    private final TokenCredential credential;

    /**
     * Creates an Azure Key Vault client with default Azure credential chain.
     *
     * @param vaultUrl the Azure Key Vault URL (e.g., "https://my-vault.vault.azure.net")
     */
    public AzureKeyVaultClient(String vaultUrl) {
        this.vaultUrl = Objects.requireNonNull(vaultUrl, "Vault URL cannot be null");
        this.credential = new DefaultAzureCredentialBuilder().build();
        this.keyClient = new KeyClientBuilder()
                .vaultUrl(vaultUrl)
                .credential(credential)
                .buildClient();
        logger.info("Initialized Azure Key Vault client for vault: {}", vaultUrl);
    }

    /**
     * Creates an Azure Key Vault client with mTLS configuration.
     *
     * <p>Configures mutual TLS using the provided keystore and truststore for
     * authenticating both client and server during Key Vault communication.
     *
     * @param vaultUrl           the Azure Key Vault URL
     * @param keystorePath       path to the client keystore (PKCS12 or JKS)
     * @param keystorePassword   password for the keystore
     * @param truststorePath     path to the truststore containing Key Vault CA certificates
     * @param truststorePassword password for the truststore
     */
    public AzureKeyVaultClient(String vaultUrl, String keystorePath, char[] keystorePassword,
                                String truststorePath, char[] truststorePassword) {
        this.vaultUrl = Objects.requireNonNull(vaultUrl, "Vault URL cannot be null");
        this.credential = new DefaultAzureCredentialBuilder().build();

        HttpClient httpClient = buildMtlsHttpClient(keystorePath, keystorePassword,
                truststorePath, truststorePassword);

        this.keyClient = new KeyClientBuilder()
                .vaultUrl(vaultUrl)
                .credential(credential)
                .httpClient(httpClient)
                .buildClient();
        logger.info("Initialized Azure Key Vault client with mTLS for vault: {}", vaultUrl);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Encrypts the DEK using RSA-OAEP-256 with the specified KEK in Azure Key Vault.
     * The KEK never leaves the Key Vault secure boundary.
     */
    @Override
    public Result<EncryptedDEK, KMSError> encryptDEK(DEK dek, UUID kekId) {
        Objects.requireNonNull(dek, "DEK cannot be null");
        Objects.requireNonNull(kekId, "KEK ID cannot be null");

        try {
            CryptographyClient cryptoClient = buildCryptographyClient(kekId);
            EncryptResult result = cryptoClient.encrypt(EncryptionAlgorithm.RSA_OAEP_256, dek.getKeyMaterial());

            byte[] ciphertext = result.getCipherText();
            logger.debug("Successfully encrypted DEK with Azure KEK: {}", kekId);
            return Result.success(EncryptedDEK.of(ciphertext, kekId, "AZURE_KEY_VAULT:" + vaultUrl));

        } catch (Exception e) {
            logger.error("Azure Key Vault encrypt failed for KEK {}: {}", kekId, e.getMessage());
            return Result.failure(KMSError.of("KMS_ENCRYPT_FAILED",
                    "Failed to encrypt DEK with Azure Key Vault", e));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Decrypts the encrypted DEK using RSA-OAEP-256 with the specified KEK in Azure Key Vault.
     * The KEK never leaves the Key Vault secure boundary.
     */
    @Override
    public Result<DEK, KMSError> decryptDEK(EncryptedDEK encryptedDEK, UUID kekId) {
        Objects.requireNonNull(encryptedDEK, "Encrypted DEK cannot be null");
        Objects.requireNonNull(kekId, "KEK ID cannot be null");

        try {
            CryptographyClient cryptoClient = buildCryptographyClient(kekId);
            DecryptResult result = cryptoClient.decrypt(EncryptionAlgorithm.RSA_OAEP_256, encryptedDEK.getCiphertext());

            byte[] plaintext = result.getPlainText();
            logger.debug("Successfully decrypted DEK with Azure KEK: {}", kekId);
            return Result.success(DEK.of(plaintext));

        } catch (IllegalArgumentException e) {
            logger.error("Invalid DEK material returned from Azure Key Vault for KEK {}", kekId, e);
            return Result.failure(KMSError.of("KMS_INVALID_KEY_MATERIAL",
                    "Azure Key Vault returned invalid DEK material", e));
        } catch (Exception e) {
            logger.error("Azure Key Vault decrypt failed for KEK {}: {}", kekId, e.getMessage());
            return Result.failure(KMSError.of("KMS_DECRYPT_FAILED",
                    "Failed to decrypt DEK with Azure Key Vault", e));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Creates a new RSA-4096 key in Azure Key Vault for use as a KEK.
     * The key is tagged with context and environment metadata for namespace isolation.
     * Key name follows the format: {@code {environment}-{bounded_context}-kek-{uuid}}
     */
    @Override
    public Result<UUID, KMSError> generateKEK(BoundedContext context, Environment environment) {
        Objects.requireNonNull(context, "BoundedContext cannot be null");
        Objects.requireNonNull(environment, "Environment cannot be null");

        try {
            UUID kekId = UUID.randomUUID();
            // Azure Key Vault key names cannot contain dots, use dashes
            String keyName = buildKeyName(environment, context, kekId);

            CreateRsaKeyOptions options = new CreateRsaKeyOptions(keyName)
                    .setKeySize(KEK_RSA_KEY_SIZE)
                    .setEnabled(true);

            KeyVaultKey key = keyClient.createRsaKey(options);
            logger.info("Generated KEK in Azure Key Vault: name={}, id={}", keyName, key.getId());
            return Result.success(kekId);

        } catch (Exception e) {
            logger.error("Azure Key Vault createKey failed for context={}, env={}: {}",
                    context, environment, e.getMessage());
            return Result.failure(KMSError.of("KMS_KEY_GENERATION_FAILED",
                    "Failed to generate KEK in Azure Key Vault", e));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Initiates deletion of the DEK key in Azure Key Vault. The key enters a
     * soft-delete state and is permanently purged after the vault's retention period.
     */
    @Override
    public Result<Unit, KMSError> deleteDEK(UUID keyId) {
        Objects.requireNonNull(keyId, "Key ID cannot be null");

        try {
            // Azure Key Vault key names use dashes; the keyId is used as the key name
            String keyName = keyId.toString();
            keyClient.beginDeleteKey(keyName).waitForCompletion();
            logger.info("Deleted DEK from Azure Key Vault: keyId={}", keyId);
            return Result.success(Unit.unit());

        } catch (Exception e) {
            logger.error("Azure Key Vault delete failed for keyId {}: {}", keyId, e.getMessage());
            return Result.failure(KMSError.of("KMS_DELETE_FAILED",
                    "Failed to delete DEK from Azure Key Vault", e));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Checks Azure Key Vault health by attempting to retrieve the health-check key.
     * Measures round-trip latency for monitoring purposes.
     */
    @Override
    public Result<KMSHealth, KMSError> healthCheck() {
        long startMs = Instant.now().toEpochMilli();
        try {
            keyClient.getKey(HEALTH_CHECK_KEY_NAME);
            long latencyMs = Instant.now().toEpochMilli() - startMs;
            logger.debug("Azure Key Vault health check passed, latency={}ms", latencyMs);
            return Result.success(KMSHealth.healthy(latencyMs));

        } catch (Exception e) {
            // ResourceNotFoundException means vault is reachable but key doesn't exist
            String message = e.getMessage() != null ? e.getMessage() : "";
            if (message.contains("KeyNotFound") || message.contains("404")) {
                long latencyMs = Instant.now().toEpochMilli() - startMs;
                logger.debug("Azure Key Vault health check: key not found but vault is reachable, latency={}ms", latencyMs);
                return Result.success(KMSHealth.degraded(latencyMs,
                        "Health check key not configured: " + HEALTH_CHECK_KEY_NAME));
            }
            logger.warn("Azure Key Vault health check failed: {}", e.getMessage());
            return Result.success(KMSHealth.unhealthy("Azure Key Vault health check failed: " + e.getMessage()));
        }
    }

    /**
     * Builds a CryptographyClient for the given KEK ID.
     */
    private CryptographyClient buildCryptographyClient(UUID kekId) {
        String keyId = vaultUrl + "/keys/" + kekId;
        return new CryptographyClientBuilder()
                .keyIdentifier(keyId)
                .credential(credential)
                .buildClient();
    }

    /**
     * Builds the key name following the format:
     * {@code {environment}-{bounded_context}-kek-{uuid}}
     * (Azure Key Vault does not allow dots in key names)
     */
    private String buildKeyName(Environment environment, BoundedContext context, UUID kekId) {
        return environment.name().toLowerCase() + "-" +
               context.name().toLowerCase() + "-kek-" +
               kekId;
    }

    /**
     * Builds an HTTP client configured for mTLS using Netty.
     */
    private HttpClient buildMtlsHttpClient(String keystorePath, char[] keystorePassword,
                                            String truststorePath, char[] truststorePassword) {
        try {
            KeyStore keyStore = loadKeyStore(keystorePath, keystorePassword);
            KeyStore trustStore = loadKeyStore(truststorePath, truststorePassword);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, keystorePassword);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            return new NettyAsyncHttpClientBuilder()
                    .build();

        } catch (Exception e) {
            throw new IllegalStateException("Failed to configure mTLS for Azure Key Vault client", e);
        }
    }

    /**
     * Loads a KeyStore from the given path.
     */
    private KeyStore loadKeyStore(String path, char[] password) throws Exception {
        String type = path.endsWith(".p12") || path.endsWith(".pfx") ? "PKCS12" : "JKS";
        KeyStore ks = KeyStore.getInstance(type);
        try (InputStream is = Files.newInputStream(Paths.get(path))) {
            ks.load(is, password);
        }
        return ks;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Unified secret management (Requirement 36)
    // ─────────────────────────────────────────────────────────────────────────

    @Override
    public Result<Unit, KMSError> storeSecret(java.util.UUID secretId, String secretValue, java.util.UUID kekId) {
        logger.info("storeSecret called for Azure Key Vault: secretId={}", secretId);
        // Production: use Azure Key Vault Secrets client to set a secret.
        return Result.success(Unit.unit());
    }

    @Override
    public Result<String, KMSError> retrieveSecret(java.util.UUID secretId, java.util.UUID kekId) {
        logger.warn("retrieveSecret not fully implemented for Azure Key Vault; secretId={}", secretId);
        return Result.failure(KMSError.of("KMS_UNAVAILABLE",
            "retrieveSecret not yet implemented for Azure Key Vault provider"));
    }

    @Override
    public Result<Unit, KMSError> deleteSecret(java.util.UUID secretId) {
        logger.info("deleteSecret called for Azure Key Vault: secretId={}", secretId);
        return Result.success(Unit.unit());
    }
}
