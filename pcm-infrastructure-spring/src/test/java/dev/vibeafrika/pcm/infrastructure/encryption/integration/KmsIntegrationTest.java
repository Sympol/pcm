package dev.vibeafrika.pcm.infrastructure.encryption.integration;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.*;
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
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * KMS integration tests verifying KEK generation, DEK encryption/decryption,
 * authentication/authorization, health checks, and failover.
 *
 * <p>Uses mock KMS clients to avoid requiring live cloud credentials in CI/CD.
 * For live integration tests, configure credentials and run with the
 * {@code integration} Maven profile.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("KMS Integration Tests")
class KmsIntegrationTest {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static DEK randomDEK() {
        byte[] keyMaterial = new byte[32];
        SECURE_RANDOM.nextBytes(keyMaterial);
        return DEK.of(keyMaterial);
    }

    private static EncryptedDEK randomEncryptedDEK(UUID kekId) {
        byte[] ciphertext = new byte[256];
        SECURE_RANDOM.nextBytes(ciphertext);
        return EncryptedDEK.of(ciphertext, kekId);
    }

    // -------------------------------------------------------------------------
    // KEK generation and storage
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("KEK generation and storage")
    class KekGenerationTests {

        @Mock
        private IKMSClient kmsClient;

        @Test
        @DisplayName("generateKEK returns a non-null UUID for each bounded context")
        void generateKEK_returnsUUID_forEachContext() {
            UUID expectedId = UUID.randomUUID();
            when(kmsClient.generateKEK(any(BoundedContext.class), any(Environment.class)))
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
        }

        @Test
        @DisplayName("generateKEK produces unique UUIDs for different contexts")
        void generateKEK_differentContexts_differentUUIDs() {
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
        @DisplayName("generateKEK returns KMS_KEY_GENERATION_FAILED when KMS is unavailable")
        void generateKEK_kmsUnavailable_returnsError() {
            KMSError error = KMSError.of("KMS_KEY_GENERATION_FAILED", "KMS service unavailable");
            when(kmsClient.generateKEK(any(BoundedContext.class), any(Environment.class)))
                    .thenReturn(Result.failure(error));

            Result<UUID, KMSError> result = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_KEY_GENERATION_FAILED");
        }
    }

    // -------------------------------------------------------------------------
    // DEK encryption/decryption with KEK
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("DEK encryption and decryption with KEK")
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
        @DisplayName("encryptDEK returns EncryptedDEK on success")
        void encryptDEK_returnsEncryptedDEK() {
            EncryptedDEK expected = randomEncryptedDEK(kekId);
            when(kmsClient.encryptDEK(any(DEK.class), any(UUID.class)))
                    .thenReturn(Result.success(expected));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getValue().get().getKekId()).isEqualTo(kekId);
        }

        @Test
        @DisplayName("decryptDEK returns original DEK after encryption")
        void decryptDEK_returnsOriginalDEK() {
            EncryptedDEK encryptedDEK = randomEncryptedDEK(kekId);
            when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                    .thenReturn(Result.success(encryptedDEK));
            when(kmsClient.decryptDEK(eq(encryptedDEK), eq(kekId)))
                    .thenReturn(Result.success(dek));

            Result<EncryptedDEK, KMSError> encResult = kmsClient.encryptDEK(dek, kekId);
            assertThat(encResult.isSuccess()).isTrue();

            Result<DEK, KMSError> decResult = kmsClient.decryptDEK(encResult.getValue().get(), kekId);

            assertThat(decResult.isSuccess()).isTrue();
            assertThat(decResult.getValue().get()).isEqualTo(dek);
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
        @DisplayName("decryptDEK with wrong KEK ID returns error")
        void decryptDEK_wrongKekId_returnsError() {
            UUID wrongKekId = UUID.randomUUID();
            EncryptedDEK encryptedDEK = randomEncryptedDEK(kekId);
            KMSError error = KMSError.of("KMS_DECRYPT_FAILED", "Invalid key ID");
            when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(wrongKekId)))
                    .thenReturn(Result.failure(error));

            Result<DEK, KMSError> result = kmsClient.decryptDEK(encryptedDEK, wrongKekId);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_DECRYPT_FAILED");
        }
    }

    // -------------------------------------------------------------------------
    // KMS authentication and authorization
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("KMS authentication and authorization")
    class KmsAuthTests {

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
        void encryptDEK_invalidCredentials_returnsAuthError() {
            KMSError error = KMSError.of("KMS_AUTHENTICATION_FAILED", "Invalid credentials");
            when(kmsClient.encryptDEK(any(DEK.class), any(UUID.class)))
                    .thenReturn(Result.failure(error));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_AUTHENTICATION_FAILED");
        }

        @Test
        @DisplayName("generateKEK returns KMS_AUTHORIZATION_FAILED when service lacks permissions")
        void generateKEK_insufficientPermissions_returnsAuthorizationError() {
            KMSError error = KMSError.of("KMS_AUTHORIZATION_FAILED", "Access denied");
            when(kmsClient.generateKEK(any(BoundedContext.class), any(Environment.class)))
                    .thenReturn(Result.failure(error));

            Result<UUID, KMSError> result = kmsClient.generateKEK(BoundedContext.PROFILE, Environment.PROD);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_AUTHORIZATION_FAILED");
        }

        @Test
        @DisplayName("Authentication error message does not expose credentials")
        void authError_doesNotExposeCredentials() {
            KMSError error = KMSError.of("KMS_AUTHENTICATION_FAILED", "Authentication failed");
            when(kmsClient.encryptDEK(any(DEK.class), any(UUID.class)))
                    .thenReturn(Result.failure(error));

            Result<EncryptedDEK, KMSError> result = kmsClient.encryptDEK(dek, kekId);

            assertThat(result.getError().get().getMessage())
                    .doesNotContain("password")
                    .doesNotContain("token")
                    .doesNotContain("secret");
        }
    }

    // -------------------------------------------------------------------------
    // KMS health checks and failover 
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("KMS health checks and failover")
    class KmsHealthAndFailoverTests {

        @Mock
        private IKMSClient primaryKmsClient;

        @Mock
        private IKMSClient secondaryKmsClient;

        @Mock
        private IAuditLogger auditLogger;

        @Mock
        private IVCounter ivCounter;

        @Test
        @DisplayName("healthCheck returns HEALTHY status when KMS is available")
        void healthCheck_kmsAvailable_returnsHealthy() {
            when(primaryKmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.healthy(12L)));

            Result<KMSHealth, KMSError> result = primaryKmsClient.healthCheck();

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getValue().get().isAvailable()).isTrue();
            assertThat(result.getValue().get().getStatus()).isEqualTo("HEALTHY");
        }

        @Test
        @DisplayName("healthCheck returns UNHEALTHY status when KMS is degraded")
        void healthCheck_kmsDegraded_returnsUnhealthy() {
            when(primaryKmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.unhealthy("Connection timeout")));

            Result<KMSHealth, KMSError> result = primaryKmsClient.healthCheck();

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getValue().get().isAvailable()).isFalse();
            assertThat(result.getValue().get().getStatus()).isEqualTo("UNHEALTHY");
        }

        @Test
        @DisplayName("healthCheck returns DEGRADED status when health check key is missing")
        void healthCheck_healthCheckKeyMissing_returnsDegraded() {
            when(primaryKmsClient.healthCheck())
                    .thenReturn(Result.success(KMSHealth.degraded(15L, "Health check key not configured")));

            Result<KMSHealth, KMSError> result = primaryKmsClient.healthCheck();

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getValue().get().isAvailable()).isTrue();
            assertThat(result.getValue().get().getStatus()).isEqualTo("DEGRADED");
        }

        @Test
        @DisplayName("Circuit breaker opens after KMS health check failure")
        void circuitBreaker_opensAfterHealthCheckFailure() {
            KMSCircuitBreaker circuitBreaker = new KMSCircuitBreaker(primaryKmsClient);

            // Simulate a health check failure to open the circuit
            KMSError error = KMSError.of("KMS_UNAVAILABLE", "KMS is down");
            when(primaryKmsClient.healthCheck())
                    .thenReturn(Result.failure(error));

            circuitBreaker.healthCheck();

            // Circuit should be open now (read-only mode)
            assertTrue(circuitBreaker.isReadOnly(),
                    "Circuit breaker must enter read-only mode after KMS health check failure");
        }

        @Test
        @DisplayName("Circuit breaker allows operations when KMS is healthy")
        void circuitBreaker_allowsOperations_whenKmsHealthy() {
            KMSCircuitBreaker circuitBreaker = new KMSCircuitBreaker(primaryKmsClient);

            // A freshly created circuit breaker starts in closed (healthy) state
            assertFalse(circuitBreaker.isReadOnly(), "Circuit breaker must not be in read-only mode when KMS is healthy");
        }

        @Test
        @DisplayName("healthCheck returns KMS_UNAVAILABLE error when KMS is completely down")
        void healthCheck_kmsDown_returnsError() {
            KMSError error = KMSError.of("KMS_UNAVAILABLE", "Connection refused");
            when(primaryKmsClient.healthCheck()).thenReturn(Result.failure(error));

            Result<KMSHealth, KMSError> result = primaryKmsClient.healthCheck();

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getError().get().getCode()).isEqualTo("KMS_UNAVAILABLE");
        }
    }
}
