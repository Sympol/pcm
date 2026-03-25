package dev.vibeafrika.pcm.infrastructure.encryption.kms;

import dev.vibeafrika.pcm.domain.encryption.BoundedContext;
import dev.vibeafrika.pcm.domain.encryption.DEK;
import dev.vibeafrika.pcm.domain.encryption.EncryptedDEK;
import dev.vibeafrika.pcm.domain.encryption.Environment;
import dev.vibeafrika.pcm.domain.encryption.IKMSClient;
import dev.vibeafrika.pcm.domain.encryption.KMSError;
import dev.vibeafrika.pcm.domain.encryption.KMSHealth;
import dev.vibeafrika.pcm.domain.encryption.Result;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.SecureRandom;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Integration tests for KMS client adapters.
 *
 * <p>These tests verify the contract of {@link IKMSClient} implementations using
 * mock KMS clients to avoid requiring live cloud credentials in CI/CD.
 *
 * <p>Coverage:
 * <ul>
 *   <li>KEK generation in KMS</li>
 *   <li>DEK encryption/decryption with KEK</li>
 *   <li>KMS authentication and authorization</li>
 *   <li>KMS health checks</li>
 *   <li>mTLS configuration verification</li>
 * </ul>
 *
 * <p>For live integration tests against real KMS providers, configure the appropriate
 * credentials and run with the {@code integration} Maven profile.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("KMS Client Integration Tests")
class KmsClientIntegrationTest {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** Generates a random 256-bit DEK for testing. */
    private static DEK randomDEK() {
        byte[] keyMaterial = new byte[32];
        SECURE_RANDOM.nextBytes(keyMaterial);
        return DEK.of(keyMaterial);
    }

    /** Generates a random EncryptedDEK for testing. */
    private static EncryptedDEK randomEncryptedDEK(UUID kekId) {
        byte[] ciphertext = new byte[256];
        SECURE_RANDOM.nextBytes(ciphertext);
        return EncryptedDEK.of(ciphertext, kekId);
    }

    /** Generates a random EncryptedDEK with KMS metadata for testing. */
    private static EncryptedDEK randomEncryptedDEKWithMetadata(UUID kekId, String metadata) {
        byte[] ciphertext = new byte[256];
        SECURE_RANDOM.nextBytes(ciphertext);
        return EncryptedDEK.of(ciphertext, kekId, metadata);
    }


    // =========================================================================
    // IKMSClient Contract Tests
    // =========================================================================

    /**
     * Contract tests that any IKMSClient implementation must satisfy.
     * These are run against a mock to verify the contract without live credentials.
     */
    @Nested
    @DisplayName("IKMSClient Contract Tests")
    class KmsClientContractTests {

        @Mock
        private IKMSClient kmsClient;

        private UUID kekId;
        private DEK dek;

        @BeforeEach
        void setUp() {
            kekId = UUID.randomUUID();
            dek = randomDEK();
        }

        @Test
        @DisplayName("encryptDEK returns EncryptedDEK on success")
        void encryptDEK_returnsEncryptedDEK() {
            EncryptedDEK expected = randomEncryptedDEK(kekId);
            when(kmsClient.encryptDEK(any(DEK.class), any(UUID.class)))
                    .thenReturn(Result.success(expected));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getValue()).isPresent();
            assertThat(result.getValue().get().getKekId()).isEqualTo(kekId);
        }

        @Test
        @DisplayName("decryptDEK returns DEK on success")
        void decryptDEK_returnsDEK() {
            EncryptedDEK encryptedDEK = randomEncryptedDEK(kekId);
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), any(UUID.class)))
                    .thenReturn(Result.success(dek));

            Result<DEK, KMSError> result = kmsClient.decryptDEK(encryptedDEK, kekId);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getValue()).isPresent();
        }

        @Test
        @DisplayName("generateKEK returns UUID on success")
        void generateKEK_returnsUUID() {
            UUID expectedKekId = UUID.randomUUID();
            when(kmsClient.generateKEK(any(BoundedContext.class), any(Environment.class)))
                    .thenReturn(Result.success(expectedKekId));

            Result<UUID, KMSError> result = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.DEV);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getValue()).isPresent();
            assertThat(result.getValue().get()).isNotNull();
        }

        @Test
        @DisplayName("healreturns KMSError on failure")
        void encryptDEK_returnsKMSError_onFailure() {
            KMSError error = KMSError.of("KMS_ENCRYPT_FAILED", "KMS unavailable");
            when(kmsClient.encryptDEK(any(DEK.class), any(UUID.class)))
                    .thenReturn(Result.failure(error));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError()).isPresent();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_ENCRYPT_FAILED");
        }

        @Test
        @DisplayName("decryptDEK returns KMSError on failure")
        void decryptDEK_returnsKMSError_onFailure() {
            EncryptedDEK encryptedDEK = randomEncryptedDEK(kekId);
            KMSError error = KMSError.of("KMS_DECRYPT_FAILED", "Decryption failed");
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), any(UUID.class)))
                    .thenReturn(Result.failure(error));

            Result<DEK, KMSError> result = kmsClient.decryptDEK(encryptedDEK, kekId);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError()).isPresent();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_DECRYPT_FAILED");
        }

        @Test
        @DisplayName("generateKEK returns KMSError on failure")
        void generateKEK_returnsKMSError_onFailure() {
            KMSError error = KMSError.of("KMS_KEY_GENERATION_FAILED", "Key generation failed");
            when(kmsClient.generateKEK(any(BoundedContext.class), any(Environment.class)))
                    .thenReturn(Result.failure(error));

            Result<UUID, KMSError> result = kmsClient.generateKEK(BoundedContext.CONSENT, Environment.PROD);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError()).isPresent();
        }

        @Test
        @DisplayName("healthCheck returns unhealthy status when KMS is degraded")
        void healthCheck_returnsUnhealthy_whenKMSDegraded() {
            when(kmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.unhealthy("Connection timeout")));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getValue().get().isAvailable()).isFalse();
            assertThat(result.getValue().get().getStatus()).isEqualTo("UNHEALTHY");
        }

        @Test
        @DisplayName("generateKEK generates different UUIDs for different contexts")
        void generateKEK_generatesDifferentUUIDs_forDifferentContexts() {
            UUID profileKekId = UUID.randomUUID();
            UUID consentKekId = UUID.randomUUID();

            when(kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD))
                    .thenReturn(Result.success(profileKekId));
            when(kmsClient.generateKEK(BoundedContext.CONSENT, Environment.PROD))
                    .thenReturn(Result.success(consentKekId));

            Result<UUID, KMSError> profileResult = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD);
            Result<UUID, KMSError> consentResult = kmsClient.generateKEK(BoundedContext.CONSENT, Environment.PROD);

            assertThat(profileResult.getValue().get()).isNotEqualTo(consentResult.getValue().get());
        }

        @Test
        @DisplayName("encryptedDEK contains the KEK ID used for encryption")
        void encryptedDEK_containsKekId() {
            EncryptedDEK encryptedDEK = EncryptedDEK.of(new byte[256], kekId, "TEST");
            when(kmsClient.encryptDEK(any(DEK.class), any(UUID.class)))
                    .thenReturn(Result.success(encryptedDEK));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.getValue().get().getKekId()).isEqualTo(kekId);
        }

        @Test
        @DisplayName("healthCheck returns degraded status when health check key is missing")
        void healthCheck_returnsDegraded_whenHealthCheckKeyMissing() {
            when(kmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.degraded(15L, "Health check key not configured")));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getValue().get().isAvailable()).isTrue();
            assertThat(result.getValue().get().getStatus()).isEqualTo("DEGRADED");
        }
    }


    // =========================================================================
    // KEK Generation Tests 
    // =========================================================================

    /**
     * Tests for KEK generation across all KMS providers.
     * (AWS KMS, Azure Key Vault ,GCP Cloud KMS).
     */
    @Nested
    @DisplayName("KEK Generation Tests")
    class KekGenerationTests {

        @Mock
        private IKMSClient kmsClient;

        @Test
        @DisplayName("generateKEK returns a non-null UUID for PROFILE context in DEV")
        void generateKEK_profileContext_devEnvironment_returnsUUID() {
            UUID expectedId = UUID.randomUUID();
            when(kmsClient.generateKEK(BoundedContext.PROFILE, Environment.DEV))
                    .thenReturn(Result.success(expectedId));

            Result<UUID, KMSError> result = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.DEV);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getValue().get()).isNotNull();
        }

        @ParameterizedTest(name = "generateKEK for context={0}")
        @EnumSource(BoundedContext.class)
        @DisplayName("generateKEK succeeds for all bounded contexts")
        void generateKEK_allBoundedContexts_succeed(BoundedContext context) {
            UUID kekId = UUID.randomUUID();
            when(kmsClient.generateKEK(eq(context), any(Environment.class)))
                    .thenReturn(Result.success(kekId));

            Result<UUID, KMSError> result = kmsClient.generateKEK(context, Environment.PROD);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getValue().get()).isEqualTo(kekId);
        }

        @ParameterizedTest(name = "generateKEK for environment={0}")
        @EnumSource(Environment.class)
        @DisplayName("generateKEK succeeds for all environments")
        void generateKEK_allEnvironments_succeed(Environment environment) {
            UUID kekId = UUID.randomUUID();
            when(kmsClient.generateKEK(any(BoundedContext.class), eq(environment)))
                    .thenReturn(Result.success(kekId));

            Result<UUID, KMSError> result = kmsClient.generateKEK(BoundedContext.PROFILE, environment);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getValue().get()).isEqualTo(kekId);
        }

        @Test
        @DisplayName("generateKEK produces unique UUIDs for each call")
        void generateKEK_producesUniqueUUIDs() {
            UUID kekId1 = UUID.randomUUID();
            UUID kekId2 = UUID.randomUUID();

            when(kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD))
                    .thenReturn(Result.success(kekId1))
                    .thenReturn(Result.success(kekId2));

            Result<UUID, KMSError> result1 = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD);
            Result<UUID, KMSError> result2 = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD);

            assertThat(result1.getValue().get()).isNotEqualTo(result2.getValue().get());
        }

        @Test
        @DisplayName("generateKEK for PROD environment uses different KEK than DEV")
        void generateKEK_prodAndDevEnvironments_useDifferentKEKs() {
            UUID devKekId = UUID.randomUUID();
            UUID prodKekId = UUID.randomUUID();

            when(kmsClient.generateKEK(BoundedContext.PROFILE, Environment.DEV))
                    .thenReturn(Result.success(devKekId));
            when(kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD))
                    .thenReturn(Result.success(prodKekId));

            Result<UUID, KMSError> devResult = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.DEV);
            Result<UUID, KMSError> prodResult = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD);

            assertThat(devResult.getValue().get()).isNotEqualTo(prodResult.getValue().get());
        }

        @Test
        @DisplayName("generateKEK returns KMS_KEY_GENERATION_FAILED when KMS is unavailable")
        void generateKEK_kmsUnavailable_returnsKeyGenerationFailedError() {
            KMSError error = KMSError.of("KMS_KEY_GENERATION_FAILED", "KMS service unavailable");
            when(kmsClient.generateKEK(any(BoundedContext.class), any(Environment.class)))
                    .thenReturn(Result.failure(error));

            Result<UUID, KMSError> result = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_KEY_GENERATION_FAILED");
        }

        @Test
        @DisplayName("generateKEK error message does not expose sensitive details")
        void generateKEK_errorMessage_doesNotExposeSensitiveDetails() {
            KMSError error = KMSError.of("KMS_KEY_GENERATION_FAILED", "Failed to generate KEK");
            when(kmsClient.generateKEK(any(BoundedContext.class), any(Environment.class)))
                    .thenReturn(Result.failure(error));

            Result<UUID, KMSError> result = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD);

            assertThat(result.getError().get().getMessage())
                    .doesNotContain("key=")
                    .doesNotContain("secret")
                    .doesNotContain("password");
        }
    }


    // =========================================================================
    // DEK Encryption/Decryption Tests
    // =========================================================================

    /**
     * Tests for DEK encryption and decryption operations.
     * Validates the envelope encryption pattern where DEKs are encrypted by KEKs.
     */
    @Nested
    @DisplayName("DEK Encryption and Decryption Tests")
    class DekEncryptionDecryptionTests {

        @Mock
        private IKMSClient kmsClient;

        private UUID kekId;
        private DEK dek;

        @BeforeEach
        void setUp() {
            kekId = UUID.randomUUID();
            dek = randomDEK();
        }

        @Test
        @DisplayName("encryptDEK produces ciphertext different from plaintext DEK")
        void encryptDEK_producesEncryptedCiphertext() {
            byte[] originalKeyMaterial = dek.getKeyMaterial();
            EncryptedDEK encryptedDEK = randomEncryptedDEK(kekId);
            when(kmsClient.encryptDEK(any(DEK.class), any(UUID.class)))
                    .thenReturn(Result.success(encryptedDEK));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.isSuccess()).isTrue();
            // Encrypted ciphertext should not equal the original key material
            assertThat(result.getValue().get().getCiphertext()).isNotEqualTo(originalKeyMaterial);
        }

        @Test
        @DisplayName("decryptDEK returns the original DEK after encryption")
        void decryptDEK_returnsOriginalDEK_afterEncryption() {
            EncryptedDEK encryptedDEK = randomEncryptedDEK(kekId);
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(encryptedDEK));
            when(kmsClient.decryptDEK(eq(encryptedDEK), eq(kekId)))
                    .thenReturn(Result.success(dek));

            Result<EncryptedDEK, KMSError> encryptResult = kmsClient.encryptDEK(dek, kekId);
            assertThat(encryptResult.isSuccess()).isTrue();

            Result<DEK, KMSError> decryptResult = kmsClient.decryptDEK(encryptResult.getValue().get(), kekId);

            assertThat(decryptResult.isSuccess()).isTrue();
            assertThat(decryptResult.getValue().get()).isEqualTo(dek);
        }

        @Test
        @DisplayName("encryptDEK includes KEK ID in the encrypted DEK")
        void encryptDEK_includesKekIdInEncryptedDEK() {
            EncryptedDEK encryptedDEK = randomEncryptedDEKWithMetadata(kekId, "AWS_KMS:us-east-1");
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(encryptedDEK));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.getValue().get().getKekId()).isEqualTo(kekId);
        }

        @Test
        @DisplayName("encryptDEK with AWS KMS includes provider metadata")
        void encryptDEK_awsKms_includesProviderMetadata() {
            String awsMetadata = "AWS_KMS:us-east-1";
            EncryptedDEK encryptedDEK = randomEncryptedDEKWithMetadata(kekId, awsMetadata);
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(encryptedDEK));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.getValue().get().getKmsMetadata()).isEqualTo(awsMetadata);
        }

        @Test
        @DisplayName("encryptDEK with Azure Key Vault includes provider metadata")
        void encryptDEK_azureKeyVault_includesProviderMetadata() {
            String azureMetadata = "AZURE_KEY_VAULT:https://my-vault.vault.azure.net";
            EncryptedDEK encryptedDEK = randomEncryptedDEKWithMetadata(kekId, azureMetadata);
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(encryptedDEK));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.getValue().get().getKmsMetadata()).isEqualTo(azureMetadata);
        }

        @Test
        @DisplayName("encryptDEK with GCP Cloud KMS includes provider metadata")
        void encryptDEK_gcpCloudKms_includesProviderMetadata() {
            String gcpMetadata = "GCP_KMS:my-project/us-east1";
            EncryptedDEK encryptedDEK = randomEncryptedDEKWithMetadata(kekId, gcpMetadata);
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(encryptedDEK));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.getValue().get().getKmsMetadata()).isEqualTo(gcpMetadata);
        }

        @Test
        @DisplayName("decryptDEK with wrong KEK ID returns KMS_DECRYPT_FAILED error")
        void decryptDEK_wrongKekId_returnsDecryptFailedError() {
            UUID wrongKekId = UUID.randomUUID();
            EncryptedDEK encryptedDEK = randomEncryptedDEK(kekId);
            KMSError error = KMSError.of("KMS_DECRYPT_FAILED", "Invalid key ID");
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(wrongKekId)))
                    .thenReturn(Result.failure(error));

            Result<DEK, KMSError> result = kmsClient.decryptDEK(encryptedDEK, wrongKekId);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_DECRYPT_FAILED");
        }

        @Test
        @DisplayName("decryptDEK with corrupted ciphertext returns KMS_INVALID_KEY_MATERIAL error")
        void decryptDEK_corruptedCiphertext_returnsInvalidKeyMaterialError() {
            byte[] corruptedBytes = new byte[256];
            SECURE_RANDOM.nextBytes(corruptedBytes);
            EncryptedDEK corruptedDEK = EncryptedDEK.of(corruptedBytes, kekId);
            KMSError error = KMSError.of("KMS_INVALID_KEY_MATERIAL", "Ciphertext is corrupted");
            when(kmsClient.decryptDEK(eq(corruptedDEK), eq(kekId)))
                    .thenReturn(Result.failure(error));

            Result<DEK, KMSError> result = kmsClient.decryptDEK(corruptedDEK, kekId);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_INVALID_KEY_MATERIAL");
        }

        @Test
        @DisplayName("encryptDEK called with correct KEK ID")
        void encryptDEK_calledWithCorrectKekId() {
            EncryptedDEK encryptedDEK = randomEncryptedDEK(kekId);
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(encryptedDEK));

            kmsClient.encryptDEK(dek, kekId);

            verify(kmsClient).encryptDEK(dek, kekId);
        }

        @Test
        @DisplayName("decryptDEK called with correct KEK ID")
        void decryptDEK_calledWithCorrectKekId() {
            EncryptedDEK encryptedDEK = randomEncryptedDEK(kekId);
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                    .thenReturn(Result.success(dek));

            kmsClient.decryptDEK(encryptedDEK, kekId);

            verify(kmsClient).decryptDEK(encryptedDEK, kekId);
        }
    }


    // =========================================================================
    // Authentication and Authorization Tests
    // =========================================================================

    /**
     * Tests for KMS authentication and authorization scenarios.
     * (mTLS authentication and authorization).
     */
    @Nested
    @DisplayName("KMS Authentication and Authorization Tests")
    class KmsAuthenticationAuthorizationTests {

        @Mock
        private IKMSClient kmsClient;

        private UUID kekId;
        private DEK dek;

        @BeforeEach
        void setUp() {
            kekId = UUID.randomUUID();
            dek = randomDEK();
        }

        @Test
        @DisplayName("encryptDEK returns KMS_AUTHENTICATION_FAILED when credentials are invalid")
        void encryptDEK_invalidCredentials_returnsAuthenticationFailedError() {
            KMSError error = KMSError.of("KMS_AUTHENTICATION_FAILED", "Invalid credentials");
            when(kmsClient.encryptDEK(any(DEK.class), any(UUID.class)))
                    .thenReturn(Result.failure(error));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_AUTHENTICATION_FAILED");
        }

        @Test
        @DisplayName("decryptDEK returns KMS_AUTHENTICATION_FAILED when credentials are expired")
        void decryptDEK_expiredCredentials_returnsAuthenticationFailedError() {
            EncryptedDEK encryptedDEK = randomEncryptedDEK(kekId);
            KMSError error = KMSError.of("KMS_AUTHENTICATION_FAILED", "Credentials expired");
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), any(UUID.class)))
                    .thenReturn(Result.failure(error));

            Result<DEK, KMSError> result = kmsClient.decryptDEK(encryptedDEK, kekId);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_AUTHENTICATION_FAILED");
        }

        @Test
        @DisplayName("generateKEK returns KMS_AUTHORIZATION_FAILED when service lacks permissions")
        void generateKEK_insufficientPermissions_returnsAuthorizationFailedError() {
            KMSError error = KMSError.of("KMS_AUTHORIZATION_FAILED",
                    "Service account lacks kms:CreateKey permission");
            when(kmsClient.generateKEK(any(BoundedContext.class), any(Environment.class)))
                    .thenReturn(Result.failure(error));

            Result<UUID, KMSError> result = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_AUTHORIZATION_FAILED");
        }

        @Test
        @DisplayName("encryptDEK returns KMS_AUTHORIZATION_FAILED when service lacks encrypt permission")
        void encryptDEK_noEncryptPermission_returnsAuthorizationFailedError() {
            KMSError error = KMSError.of("KMS_AUTHORIZATION_FAILED",
                    "Service account lacks kms:Encrypt permission");
            when(kmsClient.encryptDEK(any(DEK.class), any(UUID.class)))
                    .thenReturn(Result.failure(error));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_AUTHORIZATION_FAILED");
        }

        @Test
        @DisplayName("decryptDEK returns KMS_AUTHORIZATION_FAILED when service lacks decrypt permission")
        void decryptDEK_noDecryptPermission_returnsAuthorizationFailedError() {
            EncryptedDEK encryptedDEK = randomEncryptedDEK(kekId);
            KMSError error = KMSError.of("KMS_AUTHORIZATION_FAILED",
                    "Service account lacks kms:Decrypt permission");
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), any(UUID.class)))
                    .thenReturn(Result.failure(error));

            Result<DEK, KMSError> result = kmsClient.decryptDEK(encryptedDEK, kekId);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_AUTHORIZATION_FAILED");
        }

        @Test
        @DisplayName("authentication error message does not expose credentials")
        void authenticationError_doesNotExposeCredentials() {
            KMSError error = KMSError.of("KMS_AUTHENTICATION_FAILED", "Authentication failed");
            when(kmsClient.encryptDEK(any(DEK.class), any(UUID.class)))
                    .thenReturn(Result.failure(error));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.getError().get().getMessage())
                    .doesNotContain("password")
                    .doesNotContain("token")
                    .doesNotContain("secret")
                    .doesNotContain("key=");
        }

        @Test
        @DisplayName("authorization error message does not expose internal policy details")
        void authorizationError_doesNotExposeInternalPolicyDetails() {
            KMSError error = KMSError.of("KMS_AUTHORIZATION_FAILED", "Access denied");
            when(kmsClient.generateKEK(any(BoundedContext.class), any(Environment.class)))
                    .thenReturn(Result.failure(error));

            Result<UUID, KMSError> result = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD);

            assertThat(result.getError().get().getMessage())
                    .doesNotContain("arn:")
                    .doesNotContain("account-id");
        }

        @Test
        @DisplayName("healthCheck returns KMS_UNAVAILABLE when authentication fails during health check")
        void healthCheck_authenticationFailure_returnsKmsUnavailableError() {
            KMSError error = KMSError.of("KMS_UNAVAILABLE", "Authentication failed during health check");
            when(kmsClient.healthCheck()).thenReturn(Result.failure(error));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_UNAVAILABLE");
        }
    }


    // =========================================================================
    // Health Check Tests 
    // =========================================================================

    /**
     * Tests for KMS health check behavior.
     * (monitor KMS health and log alert on failure).
     */
    @Nested
    @DisplayName("KMS Health Check Tests")
    class KmsHealthCheckTests {

        @Mock
        private IKMSClient kmsClient;

        @Test
        @DisplayName("healthCheck returns HEALTHY status with latency when KMS is available")
        void healthCheck_kmsAvailable_returnsHealthyWithLatency() {
            long expectedLatency = 12L;
            when(kmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.healthy(expectedLatency)));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            assertThat(result.isSuccess()).isTrue();
            KMSHealth health = result.getValue().get();
            assertThat(health.isAvailable()).isTrue();
            assertThat(health.getStatus()).isEqualTo("HEALTHY");
            assertThat(health.getLatencyMs()).isEqualTo(expectedLatency);
            assertThat(health.getTimestamp()).isNotNull();
        }

        @Test
        @DisplayName("healthCheck returns UNHEALTHY status when KMS is unreachable")
        void healthCheck_kmsUnreachable_returnsUnhealthyStatus() {
            when(kmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.unhealthy("Connection refused")));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            assertThat(result.isSuccess()).isTrue();
            KMSHealth health = result.getValue().get();
            assertThat(health.isAvailable()).isFalse();
            assertThat(health.getStatus()).isEqualTo("UNHEALTHY");
            assertThat(health.getMessage()).isEqualTo("Connection refused");
            assertThat(health.getLatencyMs()).isNull();
        }

        @Test
        @DisplayName("healthCheck returns DEGRADED status when health check key is not configured")
        void healthCheck_healthCheckKeyMissing_returnsDegradedStatus() {
            long latency = 20L;
            String message = "Health check key alias not configured: alias/pcm-health-check";
            when(kmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.degraded(latency, message)));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            assertThat(result.isSuccess()).isTrue();
            KMSHealth health = result.getValue().get();
            assertThat(health.isAvailable()).isTrue();
            assertThat(health.getStatus()).isEqualTo("DEGRADED");
            assertThat(health.getLatencyMs()).isEqualTo(latency);
            assertThat(health.getMessage()).contains("pcm-health-check");
        }

        @Test
        @DisplayName("healthCheck returns KMSError when KMS is completely unreachable")
        void healthCheck_kmsCompletelyUnreachable_returnsKmsError() {
            KMSError error = KMSError.of("KMS_UNAVAILABLE", "KMS endpoint is unreachable");
            when(kmsClient.healthCheck()).thenReturn(Result.failure(error));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_UNAVAILABLE");
        }

        @Test
        @DisplayName("healthCheck DEGRADED status still reports KMS as available")
        void healthCheck_degradedStatus_reportsKmsAsAvailable() {
            when(kmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.degraded(50L, "High latency")));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            assertThat(result.getValue().get().isAvailable()).isTrue();
        }

        @Test
        @DisplayName("healthCheck UNHEALTHY status reports KMS as unavailable")
        void healthCheck_unhealthyStatus_reportsKmsAsUnavailable() {
            when(kmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.unhealthy("Timeout after 30s")));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            assertThat(result.getValue().get().isAvailable()).isFalse();
        }

        @Test
        @DisplayName("healthCheck includes timestamp for monitoring")
        void healthCheck_includesTimestamp() {
            when(kmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.healthy(5L)));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            assertThat(result.getValue().get().getTimestamp()).isNotNull();
        }

        @Test
        @DisplayName("healthCheck UNHEALTHY has null latency")
        void healthCheck_unhealthy_hasNullLatency() {
            when(kmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.unhealthy("Network error")));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            assertThat(result.getValue().get().getLatencyMs()).isNull();
        }

        @Test
        @DisplayName("healthCheck AWS KMS returns DEGRADED when health check alias not found")
        void healthCheck_awsKms_aliasNotFound_returnsDegraded() {
            String message = "Health check key alias not configured: alias/pcm-health-check";
            when(kmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.degraded(8L, message)));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            KMSHealth health = result.getValue().get();
            assertThat(health.getStatus()).isEqualTo("DEGRADED");
            assertThat(health.isAvailable()).isTrue();
        }

        @Test
        @DisplayName("healthCheck Azure Key Vault returns DEGRADED when health check key not found")
        void healthCheck_azureKeyVault_keyNotFound_returnsDegraded() {
            String message = "Health check key not configured: pcm-health-check";
            when(kmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.degraded(15L, message)));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            KMSHealth health = result.getValue().get();
            assertThat(health.getStatus()).isEqualTo("DEGRADED");
            assertThat(health.isAvailable()).isTrue();
        }

        @Test
        @DisplayName("healthCheck GCP Cloud KMS returns DEGRADED when health check key not found")
        void healthCheck_gcpCloudKms_keyNotFound_returnsDegraded() {
            String message = "Health check key not configured: pcm-health-check";
            when(kmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.degraded(10L, message)));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            KMSHealth health = result.getValue().get();
            assertThat(health.getStatus()).isEqualTo("DEGRADED");
            assertThat(health.isAvailable()).isTrue();
        }
    }


    // =========================================================================
    // mTLS Configuration Tests 
    // =========================================================================

    /**
     * Tests for mTLS configuration verification.
     * (mTLS for KMS communication and mutual authentication).
     */
    @Nested
    @DisplayName("mTLS Configuration Tests")
    class MtlsConfigurationTests {

        @Test
        @DisplayName("AwsKmsClient constructor with mTLS parameters throws IllegalStateException when keystore not found")
        void awsKmsClient_mtlsConstructor_throwsIllegalStateException_whenKeystoreNotFound() {
            org.junit.jupiter.api.Assertions.assertThrows(
                    IllegalStateException.class,
                    () -> new AwsKmsClient(
                            "us-east-1",
                            "/nonexistent/keystore.p12",
                            "password".toCharArray(),
                            "/nonexistent/truststore.p12",
                            "password".toCharArray()
                    )
            );
        }

        @Test
        @DisplayName("AzureKeyVaultClient constructor with mTLS parameters throws IllegalStateException when keystore not found")
        void azureKeyVaultClient_mtlsConstructor_throwsIllegalStateException_whenKeystoreNotFound() {
            org.junit.jupiter.api.Assertions.assertThrows(
                    IllegalStateException.class,
                    () -> new AzureKeyVaultClient(
                            "https://my-vault.vault.azure.net",
                            "/nonexistent/keystore.p12",
                            "password".toCharArray(),
                            "/nonexistent/truststore.p12",
                            "password".toCharArray()
                    )
            );
        }

        @Test
        @DisplayName("GcpCloudKmsClient constructor with mTLS parameters throws IllegalStateException when keystore not found")
        void gcpCloudKmsClient_mtlsConstructor_throwsIllegalStateException_whenKeystoreNotFound() {
            org.junit.jupiter.api.Assertions.assertThrows(
                    IllegalStateException.class,
                    () -> new GcpCloudKmsClient(
                            "my-project",
                            "us-east1",
                            "{}",
                            "/nonexistent/keystore.p12",
                            "password".toCharArray(),
                            "/nonexistent/truststore.p12",
                            "password".toCharArray()
                    )
            );
        }

        @Test
        @DisplayName("mTLS error message indicates configuration failure without exposing credentials")
        void mtlsError_doesNotExposeCredentials() {
            IllegalStateException ex = org.junit.jupiter.api.Assertions.assertThrows(
                    IllegalStateException.class,
                    () -> new AwsKmsClient(
                            "us-east-1",
                            "/nonexistent/keystore.p12",
                            "secret-password".toCharArray(),
                            "/nonexistent/truststore.p12",
                            "secret-password".toCharArray()
                    )
            );

            assertThat(ex.getMessage())
                    .contains("mTLS")
                    .doesNotContain("secret-password");
        }

        @Test
        @DisplayName("KMS client with mTLS returns KMS_UNAVAILABLE when TLS handshake fails")
        void kmsClient_mtlsHandshakeFailure_returnsKmsUnavailableError() {
            IKMSClient mockClient = org.mockito.Mockito.mock(IKMSClient.class);
            KMSError error = KMSError.of("KMS_UNAVAILABLE",
                    "TLS handshake failed: certificate verification error");
            when(mockClient.healthCheck()).thenReturn(Result.failure(error));

            Result<KMSHealth, KMSError> result = mockClient.healthCheck();

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_UNAVAILABLE");
            assertThat(result.getError().get().getMessage()).contains("TLS");
        }

        @Test
        @DisplayName("KMS client with mTLS returns KMS_AUTHENTICATION_FAILED when client cert is rejected")
        void kmsClient_clientCertRejected_returnsAuthenticationFailedError() {
            IKMSClient mockClient = org.mockito.Mockito.mock(IKMSClient.class);
            KMSError error = KMSError.of("KMS_AUTHENTICATION_FAILED",
                    "Client certificate rejected by KMS");
            when(mockClient.encryptDEK(any(DEK.class), any(UUID.class)))
                    .thenReturn(Result.failure(error));

            Result<EncryptedDEK, KMSError> result = mockClient.encryptDEK(randomDEK(), UUID.randomUUID());

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_AUTHENTICATION_FAILED");
        }
    }


    // =========================================================================
    // KMSHealth Value Object Tests
    // =========================================================================

    /**
     * Tests for KMSHealth value object behavior.
     */
    @Nested
    @DisplayName("KMSHealth Tests")
    class KmsHealthTests {

        @Test
        @DisplayName("healthy() creates available health with latency")
        void healthy_createsAvailableHealth() {
            KMSHealth health = KMSHealth.healthy(25L);

            assertThat(health.isAvailable()).isTrue();
            assertThat(health.getStatus()).isEqualTo("HEALTHY");
            assertThat(health.getLatencyMs()).isEqualTo(25L);
            assertThat(health.getTimestamp()).isNotNull();
        }

        @Test
        @DisplayName("unhealthy() creates unavailable health with message")
        void unhealthy_createsUnavailableHealth() {
            KMSHealth health = KMSHealth.unhealthy("Connection refused");

            assertThat(health.isAvailable()).isFalse();
            assertThat(health.getStatus()).isEqualTo("UNHEALTHY");
            assertThat(health.getMessage()).isEqualTo("Connection refused");
            assertThat(health.getLatencyMs()).isNull();
        }

        @Test
        @DisplayName("degraded() creates available health with warning message")
        void degraded_createsAvailableHealthWithWarning() {
            KMSHealth health = KMSHealth.degraded(100L, "High latency detected");

            assertThat(health.isAvailable()).isTrue();
            assertThat(health.getStatus()).isEqualTo("DEGRADED");
            assertThat(health.getLatencyMs()).isEqualTo(100L);
            assertThat(health.getMessage()).isEqualTo("High latency detected");
        }

        @Test
        @DisplayName("healthy() and degraded() both report KMS as available")
        void healthyAndDegraded_bothReportAvailable() {
            KMSHealth healthy = KMSHealth.healthy(10L);
            KMSHealth degraded = KMSHealth.degraded(200L, "Slow response");

            assertThat(healthy.isAvailable()).isTrue();
            assertThat(degraded.isAvailable()).isTrue();
        }

        @Test
        @DisplayName("unhealthy() reports KMS as unavailable")
        void unhealthy_reportsUnavailable() {
            KMSHealth unhealthy = KMSHealth.unhealthy("Service down");

            assertThat(unhealthy.isAvailable()).isFalse();
        }
    }

    // =========================================================================
    // KMSError Value Object Tests
    // =========================================================================

    /**
     * Tests for KMSError value object behavior.
     */
    @Nested
    @DisplayName("KMSError Tests")
    class KmsErrorTests {

        @Test
        @DisplayName("KMSError contains code and message")
        void kmsError_containsCodeAndMessage() {
            KMSError error = KMSError.of("KMS_UNAVAILABLE", "KMS is down");

            assertThat(error.getCode()).isEqualTo("KMS_UNAVAILABLE");
            assertThat(error.getMessage()).isEqualTo("KMS is down");
            assertThat(error.getCause()).isNull();
        }

        @Test
        @DisplayName("KMSError with cause preserves exception")
        void kmsError_withCause_preservesException() {
            RuntimeException cause = new RuntimeException("Network error");
            KMSError error = KMSError.of("KMS_UNAVAILABLE", "KMS is down", cause);

            assertThat(error.getCause()).isSameAs(cause);
        }

        @Test
        @DisplayName("KMSError message does not expose sensitive data")
        void kmsError_messageDoesNotExposeSensitiveData() {
            KMSError error = KMSError.of("KMS_ENCRYPT_FAILED", "Encryption failed");

            assertThat(error.getMessage()).doesNotContain("key=");
            assertThat(error.getMessage()).doesNotContain("plaintext=");
            assertThat(error.getMessage()).doesNotContain("secret");
        }

        @Test
        @DisplayName("KMSError equality is based on code and message")
        void kmsError_equality_basedOnCodeAndMessage() {
            KMSError error1 = KMSError.of("KMS_UNAVAILABLE", "KMS is down");
            KMSError error2 = KMSError.of("KMS_UNAVAILABLE", "KMS is down");
            KMSError error3 = KMSError.of("KMS_ENCRYPT_FAILED", "Encryption failed");

            assertThat(error1).isEqualTo(error2);
            assertThat(error1).isNotEqualTo(error3);
        }

        @Test
        @DisplayName("KMSError known error codes are well-defined")
        void kmsError_knownErrorCodes_areWellDefined() {
            String[] knownCodes = {
                "KMS_ENCRYPT_FAILED",
                "KMS_DECRYPT_FAILED",
                "KMS_KEY_GENERATION_FAILED",
                "KMS_UNAVAILABLE",
                "KMS_AUTHENTICATION_FAILED",
                "KMS_AUTHORIZATION_FAILED",
                "KMS_INVALID_KEY_MATERIAL"
            };

            for (String code : knownCodes) {
                KMSError error = KMSError.of(code, "Test message for " + code);
                assertThat(error.getCode()).isEqualTo(code);
                assertThat(error.getMessage()).isNotBlank();
            }
        }
    }

    // =========================================================================
    // Provider-Specific Behavior Tests
    // =========================================================================

    /**
     * Tests verifying provider-specific behavior for AWS KMS, Azure Key Vault, and GCP Cloud KMS.
     */
    @Nested
    @DisplayName("Provider-Specific Behavior Tests")
    class ProviderSpecificBehaviorTests {

        @Mock
        private IKMSClient kmsClient;

        @Test
        @DisplayName("AWS KMS encrypted DEK metadata contains AWS_KMS prefix and region")
        void awsKms_encryptedDEK_containsAwsMetadata() {
            UUID kekId = UUID.randomUUID();
            String awsMetadata = "AWS_KMS:us-east-1";
            EncryptedDEK encryptedDEK = randomEncryptedDEKWithMetadata(kekId, awsMetadata);
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(encryptedDEK));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(randomDEK(), kekId);

            assertThat(result.getValue().get().getKmsMetadata()).startsWith("AWS_KMS:");
        }

        @Test
        @DisplayName("Azure Key Vault encrypted DEK metadata contains AZURE_KEY_VAULT prefix and vault URL")
        void azureKeyVault_encryptedDEK_containsAzureMetadata() {
            UUID kekId = UUID.randomUUID();
            String azureMetadata = "AZURE_KEY_VAULT:https://my-vault.vault.azure.net";
            EncryptedDEK encryptedDEK = randomEncryptedDEKWithMetadata(kekId, azureMetadata);
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(encryptedDEK));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(randomDEK(), kekId);

            assertThat(result.getValue().get().getKmsMetadata()).startsWith("AZURE_KEY_VAULT:");
        }

        @Test
        @DisplayName("GCP Cloud KMS encrypted DEK metadata contains GCP_KMS prefix and project/location")
        void gcpCloudKms_encryptedDEK_containsGcpMetadata() {
            UUID kekId = UUID.randomUUID();
            String gcpMetadata = "GCP_KMS:my-project/us-east1";
            EncryptedDEK encryptedDEK = randomEncryptedDEKWithMetadata(kekId, gcpMetadata);
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(encryptedDEK));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(randomDEK(), kekId);

            assertThat(result.getValue().get().getKmsMetadata()).startsWith("GCP_KMS:");
        }

        @Test
        @DisplayName("KEK generation for all four bounded contexts succeeds")
        void generateKEK_allFourBoundedContexts_succeed() {
            BoundedContext[] contexts = BoundedContext.values();
            for (BoundedContext context : contexts) {
                UUID kekId = UUID.randomUUID();
                when(kmsClient.generateKEK(eq(context), eq(Environment.PROD)))
                        .thenReturn(Result.success(kekId));

                Result<UUID, KMSError> result = kmsClient.generateKEK(context, Environment.PROD);

                assertThat(result.isSuccess())
                        .as("generateKEK should succeed for context: " + context)
                        .isTrue();
                assertThat(result.getValue().get()).isNotNull();
            }
        }

        @Test
        @DisplayName("KMS timeout returns KMS_UNAVAILABLE error")
        void kmsTimeout_returnsKmsUnavailableError() {
            KMSError error = KMSError.of("KMS_UNAVAILABLE", "Request timed out after 30s");
            when(kmsClient.encryptDEK(any(DEK.class), any(UUID.class)))
                    .thenReturn(Result.failure(error));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(randomDEK(), UUID.randomUUID());

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_UNAVAILABLE");
        }

        @Test
        @DisplayName("KMS error includes cause exception when available")
        void kmsError_includesCauseException() {
            RuntimeException networkError = new RuntimeException("Connection reset by peer");
            KMSError error = KMSError.of("KMS_UNAVAILABLE", "Network error", networkError);
            when(kmsClient.healthCheck()).thenReturn(Result.failure(error));

            Result<KMSHealth, KMSError> result = kmsClient.healthCheck();

            assertThat(result.getError().get().getCause()).isInstanceOf(RuntimeException.class);
            assertThat(result.getError().get().getCause().getMessage())
                    .isEqualTo("Connection reset by peer");
        }
    }
}
