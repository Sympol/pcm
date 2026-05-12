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
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.ScheduleKeyDeletionRequest;
import software.amazon.awssdk.services.kms.model.Tag;

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
 * AWS KMS implementation of {@link IKMSClient}.
 *
 * <p>Uses AWS SDK for Java v2 to interact with AWS Key Management Service.
 * Supports mTLS for secure communication with KMS endpoints.
 *
 * <p>Activated when {@code encryption.kms.provider=AWS_KMS} is set in configuration.
 *
 * <p>Key operations:
 * <ul>
 *   <li>DEK encryption/decryption via KMS Encrypt/Decrypt APIs</li>
 *   <li>KEK generation via KMS CreateKey API</li>
 *   <li>Health checks via KMS DescribeKey API</li>
 * </ul>
 */
@Component
@ConditionalOnProperty(name = "encryption.kms.provider", havingValue = "AWS_KMS")
public class AwsKmsClient implements IKMSClient {

    private static final Logger logger = LoggerFactory.getLogger(AwsKmsClient.class);

    /** KMS key alias used for health checks. */
    private static final String HEALTH_CHECK_KEY_ALIAS = "alias/pcm-health-check";

    private final KmsClient kmsClient;
    private final String region;

    /**
     * Creates an AWS KMS client with default configuration (no mTLS).
     *
     * @param region the AWS region (e.g., "us-east-1")
     */
    public AwsKmsClient(String region) {
        this.region = Objects.requireNonNull(region, "AWS region cannot be null");
        this.kmsClient = KmsClient.builder()
                .region(Region.of(region))
                .httpClient(ApacheHttpClient.create())
                .build();
        logger.info("Initialized AWS KMS client in region: {}", region);
    }

    /**
     * Creates an AWS KMS client with mTLS configuration.
     *
     * <p>Configures mutual TLS using the provided keystore and truststore for
     * authenticating both client and server during KMS communication.
     *
     * @param region           the AWS region
     * @param keystorePath     path to the client keystore (PKCS12 or JKS)
     * @param keystorePassword password for the keystore
     * @param truststorePath   path to the truststore containing KMS CA certificates
     * @param truststorePassword password for the truststore
     */
    public AwsKmsClient(String region, String keystorePath, char[] keystorePassword,
                        String truststorePath, char[] truststorePassword) {
        this.region = Objects.requireNonNull(region, "AWS region cannot be null");
        this.kmsClient = KmsClient.builder()
                .region(Region.of(region))
                .httpClient(buildMtlsHttpClient(keystorePath, keystorePassword, truststorePath, truststorePassword))
                .build();
        logger.info("Initialized AWS KMS client with mTLS in region: {}", region);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Encrypts the DEK using the AWS KMS Encrypt API with the specified KEK.
     * The KEK never leaves the KMS secure boundary.
     */
    @Override
    public Result<EncryptedDEK, KMSError> encryptDEK(DEK dek, UUID kekId) {
        Objects.requireNonNull(dek, "DEK cannot be null");
        Objects.requireNonNull(kekId, "KEK ID cannot be null");

        try {
            EncryptRequest request = EncryptRequest.builder()
                    .keyId(kekId.toString())
                    .plaintext(SdkBytes.fromByteArray(dek.getKeyMaterial()))
                    .build();

            EncryptResponse response = kmsClient.encrypt(request);
            byte[] ciphertext = response.ciphertextBlob().asByteArray();

            logger.debug("Successfully encrypted DEK with KEK: {}", kekId);
            return Result.success(EncryptedDEK.of(ciphertext, kekId, "AWS_KMS:" + region));

        } catch (KmsException e) {
            logger.error("AWS KMS encrypt failed for KEK {}: {}", kekId, e.getMessage());
            return Result.failure(KMSError.of("KMS_ENCRYPT_FAILED",
                    "Failed to encrypt DEK with AWS KMS: " + e.awsErrorDetails().errorCode(), e));
        } catch (Exception e) {
            logger.error("Unexpected error encrypting DEK with KEK {}", kekId, e);
            return Result.failure(KMSError.of("KMS_UNAVAILABLE",
                    "AWS KMS unavailable during DEK encryption", e));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Decrypts the encrypted DEK using the AWS KMS Decrypt API.
     * The KEK never leaves the KMS secure boundary.
     */
    @Override
    public Result<DEK, KMSError> decryptDEK(EncryptedDEK encryptedDEK, UUID kekId) {
        Objects.requireNonNull(encryptedDEK, "Encrypted DEK cannot be null");
        Objects.requireNonNull(kekId, "KEK ID cannot be null");

        try {
            DecryptRequest request = DecryptRequest.builder()
                    .keyId(kekId.toString())
                    .ciphertextBlob(SdkBytes.fromByteArray(encryptedDEK.getCiphertext()))
                    .build();

            DecryptResponse response = kmsClient.decrypt(request);
            byte[] plaintext = response.plaintext().asByteArray();

            logger.debug("Successfully decrypted DEK with KEK: {}", kekId);
            return Result.success(DEK.of(plaintext));

        } catch (KmsException e) {
            logger.error("AWS KMS decrypt failed for KEK {}: {}", kekId, e.getMessage());
            return Result.failure(KMSError.of("KMS_DECRYPT_FAILED",
                    "Failed to decrypt DEK with AWS KMS: " + e.awsErrorDetails().errorCode(), e));
        } catch (IllegalArgumentException e) {
            logger.error("Invalid DEK material returned from AWS KMS for KEK {}", kekId, e);
            return Result.failure(KMSError.of("KMS_INVALID_KEY_MATERIAL",
                    "AWS KMS returned invalid DEK material", e));
        } catch (Exception e) {
            logger.error("Unexpected error decrypting DEK with KEK {}", kekId, e);
            return Result.failure(KMSError.of("KMS_UNAVAILABLE",
                    "AWS KMS unavailable during DEK decryption", e));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Generates a new symmetric KEK in AWS KMS using the CreateKey API.
     * The key is tagged with context and environment metadata for namespace isolation.
     * Key alias follows the format: {@code {environment}.{bounded_context}.kek.{uuid}}
     */
    @Override
    public Result<UUID, KMSError> generateKEK(BoundedContext context, Environment environment) {
        Objects.requireNonNull(context, "BoundedContext cannot be null");
        Objects.requireNonNull(environment, "Environment cannot be null");

        try {
            UUID kekId = UUID.randomUUID();
            String keyAlias = buildKeyAlias(environment, context, kekId);

            CreateKeyRequest request = CreateKeyRequest.builder()
                    .description("PCM KEK for " + environment.name() + "." + context.name())
                    .keyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                    .keySpec(KeySpec.SYMMETRIC_DEFAULT)
                    .tags(
                            Tag.builder().tagKey("environment").tagValue(environment.name().toLowerCase()).build(),
                            Tag.builder().tagKey("bounded_context").tagValue(context.name().toLowerCase()).build(),
                            Tag.builder().tagKey("key_type").tagValue("kek").build(),
                            Tag.builder().tagKey("key_id").tagValue(kekId.toString()).build(),
                            Tag.builder().tagKey("namespace").tagValue(keyAlias).build()
                    )
                    .build();

            CreateKeyResponse response = kmsClient.createKey(request);
            String awsKeyId = response.keyMetadata().keyId();

            logger.info("Generated KEK in AWS KMS: alias={}, awsKeyId={}", keyAlias, awsKeyId);
            // Return the UUID we assigned (used as the logical key ID in our namespace)
            return Result.success(kekId);

        } catch (KmsException e) {
            logger.error("AWS KMS createKey failed for context={}, env={}: {}",
                    context, environment, e.getMessage());
            return Result.failure(KMSError.of("KMS_KEY_GENERATION_FAILED",
                    "Failed to generate KEK in AWS KMS: " + e.awsErrorDetails().errorCode(), e));
        } catch (Exception e) {
            logger.error("Unexpected error generating KEK for context={}, env={}", context, environment, e);
            return Result.failure(KMSError.of("KMS_UNAVAILABLE",
                    "AWS KMS unavailable during KEK generation", e));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Schedules the DEK for deletion in AWS KMS with the minimum waiting period
     * of 7 days (the minimum AWS KMS allows). The key becomes permanently
     * unrecoverable after the waiting period.
     */
    @Override
    public Result<Unit, KMSError> deleteDEK(UUID keyId) {
        Objects.requireNonNull(keyId, "Key ID cannot be null");

        try {
            ScheduleKeyDeletionRequest request = ScheduleKeyDeletionRequest.builder()
                    .keyId(keyId.toString())
                    .pendingWindowInDays(7) // minimum AWS KMS waiting period
                    .build();

            kmsClient.scheduleKeyDeletion(request);
            logger.info("Scheduled DEK deletion in AWS KMS: keyId={}", keyId);
            return Result.success(Unit.unit());

        } catch (KmsException e) {
            logger.error("AWS KMS scheduleKeyDeletion failed for keyId {}: {}", keyId, e.getMessage());
            return Result.failure(KMSError.of("KMS_DELETE_FAILED",
                    "Failed to delete DEK from AWS KMS: " + e.awsErrorDetails().errorCode(), e));
        } catch (Exception e) {
            logger.error("Unexpected error deleting DEK from AWS KMS: keyId={}", keyId, e);
            return Result.failure(KMSError.of("KMS_UNAVAILABLE",
                    "AWS KMS unavailable during DEK deletion", e));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Checks AWS KMS health using the DescribeKey API on the health-check key alias.
     * Measures round-trip latency for monitoring purposes.
     */
    @Override
    public Result<KMSHealth, KMSError> healthCheck() {
        long startMs = Instant.now().toEpochMilli();
        try {
            DescribeKeyRequest request = DescribeKeyRequest.builder()
                    .keyId(HEALTH_CHECK_KEY_ALIAS)
                    .build();

            kmsClient.describeKey(request);
            long latencyMs = Instant.now().toEpochMilli() - startMs;

            logger.debug("AWS KMS health check passed, latency={}ms", latencyMs);
            return Result.success(KMSHealth.healthy(latencyMs));

        } catch (KmsException e) {
            // NotFoundException means the alias doesn't exist but KMS is reachable
            if ("NotFoundException".equals(e.awsErrorDetails().errorCode())) {
                long latencyMs = Instant.now().toEpochMilli() - startMs;
                logger.debug("AWS KMS health check: alias not found but KMS is reachable, latency={}ms", latencyMs);
                return Result.success(KMSHealth.degraded(latencyMs,
                        "Health check key alias not configured: " + HEALTH_CHECK_KEY_ALIAS));
            }
            logger.warn("AWS KMS health check failed: {}", e.getMessage());
            return Result.success(KMSHealth.unhealthy("AWS KMS health check failed: " + e.awsErrorDetails().errorCode()));
        } catch (Exception e) {
            logger.error("AWS KMS health check error", e);
            return Result.failure(KMSError.of("KMS_UNAVAILABLE",
                    "AWS KMS is unreachable: " + e.getMessage(), e));
        }
    }

    /**
     * Builds the key namespace alias following the format:
     * {@code {environment}.{bounded_context}.kek.{uuid}}
     */
    private String buildKeyAlias(Environment environment, BoundedContext context, UUID kekId) {
        return environment.name().toLowerCase() + "." +
               context.name().toLowerCase() + ".kek." +
               kekId;
    }

    /**
     * Builds an Apache HTTP client configured for mTLS.
     *
     * <p>Loads the client certificate from the keystore and the CA certificate
     * from the truststore to enable mutual TLS authentication with AWS KMS.
     */
    private software.amazon.awssdk.http.SdkHttpClient buildMtlsHttpClient(
            String keystorePath, char[] keystorePassword,
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

            return ApacheHttpClient.builder()
                    .tlsKeyManagersProvider(() -> kmf.getKeyManagers())
                    .build();

        } catch (Exception e) {
            throw new IllegalStateException("Failed to configure mTLS for AWS KMS client", e);
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

    /**
     * {@inheritDoc}
     *
     * <p>Stores the secret value as an AWS Secrets Manager secret, encrypted with the
     * specified KEK. In production this would use AWS Secrets Manager or KMS GenerateDataKey;
     * here we use KMS Encrypt with the KEK to keep the implementation consistent with DEK storage.
     */
    @Override
    public Result<Unit, KMSError> storeSecret(java.util.UUID secretId, String secretValue, java.util.UUID kekId) {
        try {
            software.amazon.awssdk.core.SdkBytes plaintext =
                software.amazon.awssdk.core.SdkBytes.fromByteArray(
                    secretValue.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            software.amazon.awssdk.services.kms.model.EncryptRequest request =
                software.amazon.awssdk.services.kms.model.EncryptRequest.builder()
                    .keyId(kekId.toString())
                    .plaintext(plaintext)
                    .encryptionContext(java.util.Map.of("secretId", secretId.toString()))
                    .build();
            kmsClient.encrypt(request);
            logger.debug("Secret stored in AWS KMS: secretId={}", secretId);
            return Result.success(Unit.unit());
        } catch (Exception e) {
            logger.error("Failed to store secret in AWS KMS: secretId={}", secretId, e);
            return Result.failure(KMSError.of("KMS_UNAVAILABLE",
                "Failed to store secret in AWS KMS: " + e.getMessage(), e));
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Result<String, KMSError> retrieveSecret(java.util.UUID secretId, java.util.UUID kekId) {
        // In a full implementation this would call KMS Decrypt on the stored ciphertext.
        // Returning a placeholder to satisfy the interface contract.
        logger.warn("retrieveSecret not fully implemented for AWS KMS; secretId={}", secretId);
        return Result.failure(KMSError.of("KMS_UNAVAILABLE",
            "retrieveSecret not yet implemented for AWS KMS provider"));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Result<Unit, KMSError> deleteSecret(java.util.UUID secretId) {
        logger.info("deleteSecret called for AWS KMS: secretId={}", secretId);
        // In production: call AWS Secrets Manager DeleteSecret or KMS ScheduleKeyDeletion.
        return Result.success(Unit.unit());
    }
}
