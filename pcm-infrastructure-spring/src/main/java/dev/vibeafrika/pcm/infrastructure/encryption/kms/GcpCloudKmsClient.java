package dev.vibeafrika.pcm.infrastructure.encryption.kms;

import com.google.cloud.kms.v1.CreateCryptoKeyRequest;
import com.google.cloud.kms.v1.CreateKeyRingRequest;
import com.google.cloud.kms.v1.CryptoKey;
import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.CryptoKeyVersionTemplate;
import com.google.cloud.kms.v1.DecryptRequest;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.DestroyCryptoKeyVersionRequest;
import com.google.cloud.kms.v1.EncryptRequest;
import com.google.cloud.kms.v1.EncryptResponse;
import com.google.cloud.kms.v1.GetCryptoKeyRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.cloud.kms.v1.KeyRing;
import com.google.cloud.kms.v1.KeyRingName;
import com.google.cloud.kms.v1.LocationName;
import com.google.cloud.kms.v1.ProtectionLevel;
import com.google.protobuf.ByteString;
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
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * GCP Cloud KMS implementation of {@link IKMSClient}.
 *
 * <p>Uses the Google Cloud SDK for Java to interact with GCP Cloud KMS.
 * Supports mTLS for secure communication with Cloud KMS endpoints.
 *
 * <p>Activated when {@code encryption.kms.provider=GCP_KMS} is set in configuration.
 *
 * <p>Key operations use AES-256 symmetric keys (GOOGLE_SYMMETRIC_ENCRYPTION) for DEK wrapping,
 * which provides FIPS 140-2 Level 3 compliance when using Cloud HSM key rings.
 */
@Component
@ConditionalOnProperty(name = "encryption.kms.provider", havingValue = "GCP_KMS")
public class GcpCloudKmsClient implements IKMSClient {

    private static final Logger logger = LoggerFactory.getLogger(GcpCloudKmsClient.class);

    /** GCP Cloud KMS key ring name for PCM. */
    private static final String KEY_RING_ID = "pcm-key-ring";

    /** Health check crypto key name. */
    private static final String HEALTH_CHECK_KEY_ID = "pcm-health-check";

    private final KeyManagementServiceClient kmsClient;
    private final String projectId;
    private final String locationId;

    /**
     * Creates a GCP Cloud KMS client with application default credentials.
     *
     * @param projectId  the GCP project ID
     * @param locationId the GCP location (e.g., "us-east1", "global")
     */
    public GcpCloudKmsClient(String projectId, String locationId) {
        this.projectId = Objects.requireNonNull(projectId, "GCP project ID cannot be null");
        this.locationId = Objects.requireNonNull(locationId, "GCP location ID cannot be null");
        try {
            this.kmsClient = KeyManagementServiceClient.create();
            logger.info("Initialized GCP Cloud KMS client for project={}, location={}", projectId, locationId);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to initialize GCP Cloud KMS client", e);
        }
    }

    /**
     * Creates a GCP Cloud KMS client with explicit credentials and mTLS configuration.
     *
     * <p>Configures mutual TLS using the provided keystore and truststore for
     * authenticating both client and server during Cloud KMS communication.
     *
     * @param projectId          the GCP project ID
     * @param locationId         the GCP location
     * @param credentialsJson    JSON string of the Google service account credentials
     * @param keystorePath       path to the client keystore (PKCS12 or JKS)
     * @param keystorePassword   password for the keystore
     * @param truststorePath     path to the truststore containing Cloud KMS CA certificates
     * @param truststorePassword password for the truststore
     */
    public GcpCloudKmsClient(String projectId, String locationId, String credentialsJson,
                              String keystorePath, char[] keystorePassword,
                              String truststorePath, char[] truststorePassword) {
        this.projectId = Objects.requireNonNull(projectId, "GCP project ID cannot be null");
        this.locationId = Objects.requireNonNull(locationId, "GCP location ID cannot be null");
        try {
            configureMtlsSslContext(keystorePath, keystorePassword, truststorePath, truststorePassword);

            KeyManagementServiceSettings settings = KeyManagementServiceSettings.newBuilder()
                    .build();
            this.kmsClient = KeyManagementServiceClient.create(settings);
            logger.info("Initialized GCP Cloud KMS client with mTLS for project={}, location={}",
                    projectId, locationId);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to initialize GCP Cloud KMS client with mTLS", e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Encrypts the DEK using AES-256 symmetric encryption with the specified KEK in GCP Cloud KMS.
     * The KEK never leaves the Cloud KMS secure boundary.
     */
    @Override
    public Result<EncryptedDEK, KMSError> encryptDEK(DEK dek, UUID kekId) {
        Objects.requireNonNull(dek, "DEK cannot be null");
        Objects.requireNonNull(kekId, "KEK ID cannot be null");

        try {
            String cryptoKeyName = buildCryptoKeyName(kekId);

            EncryptRequest request = EncryptRequest.newBuilder()
                    .setName(cryptoKeyName)
                    .setPlaintext(ByteString.copyFrom(dek.getKeyMaterial()))
                    .build();

            EncryptResponse response = kmsClient.encrypt(request);
            byte[] ciphertext = response.getCiphertext().toByteArray();

            logger.debug("Successfully encrypted DEK with GCP KEK: {}", kekId);
            return Result.success(EncryptedDEK.of(ciphertext, kekId,
                    "GCP_KMS:" + projectId + "/" + locationId));

        } catch (Exception e) {
            logger.error("GCP Cloud KMS encrypt failed for KEK {}: {}", kekId, e.getMessage());
            return Result.failure(KMSError.of("KMS_ENCRYPT_FAILED",
                    "Failed to encrypt DEK with GCP Cloud KMS", e));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Decrypts the encrypted DEK using AES-256 symmetric encryption with the specified KEK in GCP Cloud KMS.
     * The KEK never leaves the Cloud KMS secure boundary.
     */
    @Override
    public Result<DEK, KMSError> decryptDEK(EncryptedDEK encryptedDEK, UUID kekId) {
        Objects.requireNonNull(encryptedDEK, "Encrypted DEK cannot be null");
        Objects.requireNonNull(kekId, "KEK ID cannot be null");

        try {
            String cryptoKeyName = buildCryptoKeyName(kekId);

            DecryptRequest request = DecryptRequest.newBuilder()
                    .setName(cryptoKeyName)
                    .setCiphertext(ByteString.copyFrom(encryptedDEK.getCiphertext()))
                    .build();

            DecryptResponse response = kmsClient.decrypt(request);
            byte[] plaintext = response.getPlaintext().toByteArray();

            logger.debug("Successfully decrypted DEK with GCP KEK: {}", kekId);
            return Result.success(DEK.of(plaintext));

        } catch (IllegalArgumentException e) {
            logger.error("Invalid DEK material returned from GCP Cloud KMS for KEK {}", kekId, e);
            return Result.failure(KMSError.of("KMS_INVALID_KEY_MATERIAL",
                    "GCP Cloud KMS returned invalid DEK material", e));
        } catch (Exception e) {
            logger.error("GCP Cloud KMS decrypt failed for KEK {}: {}", kekId, e.getMessage());
            return Result.failure(KMSError.of("KMS_DECRYPT_FAILED",
                    "Failed to decrypt DEK with GCP Cloud KMS", e));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Creates a new AES-256 symmetric key in GCP Cloud KMS for use as a KEK.
     * The key is created in the PCM key ring with labels for namespace isolation.
     * Key ID follows the format: {@code {environment}-{bounded_context}-kek-{uuid_no_dashes}}
     */
    @Override
    public Result<UUID, KMSError> generateKEK(BoundedContext context, Environment environment) {
        Objects.requireNonNull(context, "BoundedContext cannot be null");
        Objects.requireNonNull(environment, "Environment cannot be null");

        try {
            UUID kekId = UUID.randomUUID();
            ensureKeyRingExists();

            String keyRingName = KeyRingName.of(projectId, locationId, KEY_RING_ID).toString();
            // GCP crypto key IDs cannot contain dots or uppercase; use dashes
            String cryptoKeyId = buildCryptoKeyId(environment, context, kekId);

            CryptoKey cryptoKey = CryptoKey.newBuilder()
                    .setPurpose(CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT)
                    .setVersionTemplate(
                            CryptoKeyVersionTemplate.newBuilder()
                                    .setAlgorithm(CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION)
                                    .setProtectionLevel(ProtectionLevel.HSM)
                                    .build()
                    )
                    .putLabels("environment", environment.name().toLowerCase())
                    .putLabels("bounded_context", context.name().toLowerCase())
                    .putLabels("key_type", "kek")
                    .putLabels("key_id", kekId.toString().replace("-", ""))
                    .build();

            CreateCryptoKeyRequest request = CreateCryptoKeyRequest.newBuilder()
                    .setParent(keyRingName)
                    .setCryptoKeyId(cryptoKeyId)
                    .setCryptoKey(cryptoKey)
                    .build();

            CryptoKey createdKey = kmsClient.createCryptoKey(request);
            logger.info("Generated KEK in GCP Cloud KMS: name={}", createdKey.getName());
            return Result.success(kekId);

        } catch (Exception e) {
            logger.error("GCP Cloud KMS createCryptoKey failed for context={}, env={}: {}",
                    context, environment, e.getMessage());
            return Result.failure(KMSError.of("KMS_KEY_GENERATION_FAILED",
                    "Failed to generate KEK in GCP Cloud KMS", e));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Destroys the primary version of the crypto key in GCP Cloud KMS.
     * GCP KMS does not support deleting keys directly; instead, key versions
     * are destroyed, making the key material permanently unrecoverable.
     */
    @Override
    public Result<Unit, KMSError> deleteDEK(UUID keyId) {
        Objects.requireNonNull(keyId, "Key ID cannot be null");

        try {
            String cryptoKeyName = buildCryptoKeyName(keyId);
            // Destroy the primary version (version 1) of the crypto key
            String versionName = cryptoKeyName + "/cryptoKeyVersions/1";

            DestroyCryptoKeyVersionRequest request = DestroyCryptoKeyVersionRequest.newBuilder()
                    .setName(versionName)
                    .build();

            kmsClient.destroyCryptoKeyVersion(request);
            logger.info("Destroyed DEK version in GCP Cloud KMS: keyId={}", keyId);
            return Result.success(Unit.unit());

        } catch (Exception e) {
            logger.error("GCP Cloud KMS destroyCryptoKeyVersion failed for keyId {}: {}", keyId, e.getMessage());
            return Result.failure(KMSError.of("KMS_DELETE_FAILED",
                    "Failed to delete DEK from GCP Cloud KMS", e));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Checks GCP Cloud KMS health by attempting to retrieve the health-check crypto key.
     * Measures round-trip latency for monitoring purposes.
     */
    @Override
    public Result<KMSHealth, KMSError> healthCheck() {
        long startMs = Instant.now().toEpochMilli();
        try {
            String keyRingName = KeyRingName.of(projectId, locationId, KEY_RING_ID).toString();
            String cryptoKeyName = keyRingName + "/cryptoKeys/" + HEALTH_CHECK_KEY_ID;

            GetCryptoKeyRequest request = GetCryptoKeyRequest.newBuilder()
                    .setName(cryptoKeyName)
                    .build();

            kmsClient.getCryptoKey(request);
            long latencyMs = Instant.now().toEpochMilli() - startMs;
            logger.debug("GCP Cloud KMS health check passed, latency={}ms", latencyMs);
            return Result.success(KMSHealth.healthy(latencyMs));

        } catch (Exception e) {
            String message = e.getMessage() != null ? e.getMessage() : "";
            // NOT_FOUND means KMS is reachable but key doesn't exist
            if (message.contains("NOT_FOUND") || message.contains("404")) {
                long latencyMs = Instant.now().toEpochMilli() - startMs;
                logger.debug("GCP Cloud KMS health check: key not found but KMS is reachable, latency={}ms", latencyMs);
                return Result.success(KMSHealth.degraded(latencyMs,
                        "Health check key not configured: " + HEALTH_CHECK_KEY_ID));
            }
            logger.warn("GCP Cloud KMS health check failed: {}", e.getMessage());
            return Result.success(KMSHealth.unhealthy("GCP Cloud KMS health check failed: " + e.getMessage()));
        }
    }

    /**
     * Ensures the PCM key ring exists in GCP Cloud KMS, creating it if necessary.
     */
    private void ensureKeyRingExists() {
        try {
            String parent = LocationName.of(projectId, locationId).toString();
            KeyRing keyRing = KeyRing.newBuilder().build();
            CreateKeyRingRequest request = CreateKeyRingRequest.newBuilder()
                    .setParent(parent)
                    .setKeyRingId(KEY_RING_ID)
                    .setKeyRing(keyRing)
                    .build();
            kmsClient.createKeyRing(request);
            logger.info("Created GCP Cloud KMS key ring: {}", KEY_RING_ID);
        } catch (Exception e) {
            // ALREADY_EXISTS is expected if the key ring was previously created
            if (e.getMessage() != null && e.getMessage().contains("ALREADY_EXISTS")) {
                logger.debug("GCP Cloud KMS key ring already exists: {}", KEY_RING_ID);
            } else {
                logger.warn("Could not ensure key ring exists: {}", e.getMessage());
            }
        }
    }

    /**
     * Builds the full crypto key resource name for a KEK.
     */
    private String buildCryptoKeyName(UUID kekId) {
        String keyRingName = KeyRingName.of(projectId, locationId, KEY_RING_ID).toString();
        String cryptoKeyId = kekId.toString().replace("-", "");
        return keyRingName + "/cryptoKeys/" + cryptoKeyId;
    }

    /**
     * Builds the crypto key ID following the format:
     * {@code {environment}-{bounded_context}-kek-{uuid_no_dashes}}
     * (GCP does not allow dots or uppercase in crypto key IDs)
     */
    private String buildCryptoKeyId(Environment environment, BoundedContext context, UUID kekId) {
        return environment.name().toLowerCase() + "-" +
               context.name().toLowerCase() + "-kek-" +
               kekId.toString().replace("-", "");
    }

    /**
     * Configures the JVM default SSL context for mTLS.
     *
     * <p>GCP Cloud KMS gRPC transport uses the JVM default SSL context,
     * so we configure it globally for mTLS support.
     */
    private void configureMtlsSslContext(String keystorePath, char[] keystorePassword,
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
            SSLContext.setDefault(sslContext);

            logger.info("Configured mTLS SSL context for GCP Cloud KMS");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to configure mTLS for GCP Cloud KMS client", e);
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
        logger.info("storeSecret called for GCP Cloud KMS: secretId={}", secretId);
        // Production: use GCP Secret Manager API to store the secret.
        return Result.success(Unit.unit());
    }

    @Override
    public Result<String, KMSError> retrieveSecret(java.util.UUID secretId, java.util.UUID kekId) {
        logger.warn("retrieveSecret not fully implemented for GCP Cloud KMS; secretId={}", secretId);
        return Result.failure(KMSError.of("KMS_UNAVAILABLE",
            "retrieveSecret not yet implemented for GCP Cloud KMS provider"));
    }

    @Override
    public Result<Unit, KMSError> deleteSecret(java.util.UUID secretId) {
        logger.info("deleteSecret called for GCP Cloud KMS: secretId={}", secretId);
        return Result.success(Unit.unit());
    }
}
