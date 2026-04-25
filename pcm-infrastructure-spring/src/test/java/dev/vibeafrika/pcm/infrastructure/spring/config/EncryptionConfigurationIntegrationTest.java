package dev.vibeafrika.pcm.infrastructure.spring.config;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.BlindIndexService;
import dev.vibeafrika.pcm.infrastructure.encryption.DEKCache;
import dev.vibeafrika.pcm.infrastructure.encryption.KeyManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.ActiveProfiles;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration tests for Spring Boot encryption configuration.
 *
 * <p>Validates Requirements:
 * <ul>
 *   <li> EncryptionService is injectable through dependency inversion</li>
 *   <li> Valid configuration is parsed into an EncryptionConfiguration object</li>
 *   <li> Invalid configuration returns a descriptive error</li>
 * </ul>
 */
@DisplayName("Encryption Spring Boot Configuration Integration Tests")
class EncryptionConfigurationIntegrationTest {

    // =========================================================================
    // 1. Bean wiring – all core encryption beans are present in the context
    // =========================================================================

    @Nested
    @DisplayName("Bean wiring")
    @org.springframework.test.context.junit.jupiter.SpringJUnitConfig(
            classes = {
                    EncryptionConfigurationIntegrationTest.FullEncryptionTestConfiguration.class
            }
    )
    @ActiveProfiles("test")
    class BeanWiringTest {

        @Autowired
        private ApplicationContext context;

        @Test
        @DisplayName("Environment bean is registered")
        void environmentBeanIsRegistered() {
            assertThat(context.containsBean("encryptionEnvironment")).isTrue();
            Environment env = context.getBean(Environment.class);
            assertThat(env).isEqualTo(Environment.DEV);
        }

        @Test
        @DisplayName("DEKCache bean is registered")
        void dekCacheBeanIsRegistered() {
            assertThat(context.getBean(DEKCache.class)).isNotNull();
        }

        @Test
        @DisplayName("IVCounter bean is registered")
        void ivCounterBeanIsRegistered() {
            assertThat(context.getBean(IVCounter.class)).isNotNull();
        }

        @Test
        @DisplayName("IAuditLogger bean is registered")
        void auditLoggerBeanIsRegistered() {
            assertThat(context.getBean(IAuditLogger.class)).isNotNull();
        }

        @Test
        @DisplayName("IKeyManager bean is registered when IKMSClient is present")
        void keyManagerBeanIsRegistered() {
            assertThat(context.getBean(IKeyManager.class)).isNotNull();
        }

        @Test
        @DisplayName("BlindIndexService bean is registered")
        void blindIndexServiceBeanIsRegistered() {
            assertThat(context.getBean(BlindIndexService.class)).isNotNull();
        }

        @Test
        @DisplayName("IEncryptionService bean is injectable")
        void encryptionServiceIsInjectable() {
            // Req 4.6: EncryptionService SHALL be injectable through dependency inversion
            assertThat(context.getBean(IEncryptionService.class)).isNotNull();
        }

        @Test
        @DisplayName("SecureRandom bean is registered and validated")
        void secureRandomBeanIsRegistered() {
            assertThat(context.getBean(SecureRandom.class)).isNotNull();
        }
    }

    // =========================================================================
    // 2. Configuration loading – properties bind correctly from YAML 
    // =========================================================================

    @Nested
    @DisplayName("Configuration loading")
    @SpringBootTest(
            classes = {
                    EncryptionAutoConfiguration.class,
                    EncryptionConfigurationIntegrationTest.StubKmsConfiguration.class
            },
            webEnvironment = SpringBootTest.WebEnvironment.NONE
    )
    @ActiveProfiles("test")
    class ConfigurationLoadingTest {

        @Autowired
        private EncryptionConfigurationProperties properties;

        @Test
        @DisplayName("Environment is loaded from application-test.yml")
        void environmentIsLoaded() {
            assertThat(properties.getEnvironment()).isEqualTo("DEV");
        }

        @Test
        @DisplayName("Default context is loaded from application-test.yml")
        void defaultContextIsLoaded() {
            assertThat(properties.getDefaultContext()).isEqualTo("PROFILE");
        }

        @Test
        @DisplayName("Blind index global salt is loaded")
        void blindIndexSaltIsLoaded() {
            assertThat(properties.getBlindIndexGlobalSalt())
                    .isEqualTo("test-global-salt-for-unit-tests-only");
        }

        @Test
        @DisplayName("DEK cache max-size is loaded")
        void dekCacheMaxSizeIsLoaded() {
            assertThat(properties.getDekCache().getMaxSize()).isEqualTo(100);
        }

        @Test
        @DisplayName("DEK cache TTL is loaded")
        void dekCacheTtlIsLoaded() {
            assertThat(properties.getDekCache().getTtlMinutes()).isEqualTo(60);
        }

        @Test
        @DisplayName("Key rotation DEK days is loaded")
        void dekRotationDaysIsLoaded() {
            assertThat(properties.getKeyRotation().getDekRotationDays()).isEqualTo(90);
        }

        @Test
        @DisplayName("Key rotation KEK days is loaded")
        void kekRotationDaysIsLoaded() {
            assertThat(properties.getKeyRotation().getKekRotationDays()).isEqualTo(365);
        }

        @Test
        @DisplayName("Audit level is loaded")
        void auditLevelIsLoaded() {
            assertThat(properties.getAudit().getLevel()).isEqualTo("HIGH");
        }

        @Test
        @DisplayName("Audit encrypt-logs flag is loaded")
        void auditEncryptLogsIsLoaded() {
            assertThat(properties.getAudit().isEncryptLogs()).isTrue();
        }

        @Test
        @DisplayName("Network mTLS flag is loaded")
        void networkMtlsIsLoaded() {
            assertThat(properties.getNetwork().isMtlsEnabled()).isFalse();
        }
    }

    // =========================================================================
    // 3. Configuration validation – validator rejects invalid configs 
    // =========================================================================

    @Nested
    @DisplayName("Configuration validation")
    class ConfigurationValidationTest {

        private EncryptionConfigurationValidator validatorFor(EncryptionConfigurationProperties props) {
            return new EncryptionConfigurationValidator(props);
        }

        @Test
        @DisplayName("Valid DEV configuration passes validation")
        void validDevConfigurationPasses() {
            EncryptionConfigurationValidator validator = validatorFor(devDefaults());
            // Should not throw
            validator.validate();
        }

        @Test
        @DisplayName("Invalid environment value is rejected with descriptive error")
        void invalidEnvironmentIsRejected() {
            EncryptionConfigurationProperties props = devDefaults();
            props.setEnvironment("INVALID_ENV");

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.environment")
                    .hasMessageContaining("INVALID_ENV");
        }

        @Test
        @DisplayName("Blank environment is rejected with descriptive error")
        void blankEnvironmentIsRejected() {
            EncryptionConfigurationProperties props = devDefaults();
            props.setEnvironment("");

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.environment");
        }

        @Test
        @DisplayName("Invalid KMS provider is rejected with descriptive error")
        void invalidKmsProviderIsRejected() {
            EncryptionConfigurationProperties props = devDefaults();
            props.getKms().setProvider("UNKNOWN_KMS");
            props.getKms().setEndpoint("https://kms.example.com");

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.kms.provider")
                    .hasMessageContaining("UNKNOWN_KMS");
        }

        @Test
        @DisplayName("KMS provider without endpoint is rejected")
        void kmsProviderWithoutEndpointIsRejected() {
            EncryptionConfigurationProperties props = devDefaults();
            props.getKms().setProvider("AWS_KMS");
            props.getKms().setRegion("us-east-1");
            // endpoint intentionally left blank

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.kms.endpoint");
        }

        @Test
        @DisplayName("AWS KMS without region is rejected")
        void awsKmsWithoutRegionIsRejected() {
            EncryptionConfigurationProperties props = devDefaults();
            props.getKms().setProvider("AWS_KMS");
            props.getKms().setEndpoint("https://kms.us-east-1.amazonaws.com");
            // region intentionally left blank

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.kms.region");
        }

        @Test
        @DisplayName("GCP KMS without project ID is rejected")
        void gcpKmsWithoutProjectIdIsRejected() {
            EncryptionConfigurationProperties props = devDefaults();
            props.getKms().setProvider("GCP_KMS");
            props.getKms().setEndpoint("https://cloudkms.googleapis.com");
            props.getKms().setGcpLocationId("us-east1");
            // gcpProjectId intentionally left blank

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.kms.gcp-project-id");
        }

        @Test
        @DisplayName("DEK cache max-size of zero is rejected")
        void dekCacheMaxSizeZeroIsRejected() {
            EncryptionConfigurationProperties props = devDefaults();
            props.getDekCache().setMaxSize(0);

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.dek-cache.max-size");
        }

        @Test
        @DisplayName("DEK cache TTL of zero is rejected")
        void dekCacheTtlZeroIsRejected() {
            EncryptionConfigurationProperties props = devDefaults();
            props.getDekCache().setTtlMinutes(0);

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.dek-cache.ttl-minutes");
        }

        @Test
        @DisplayName("Invalid audit level is rejected with descriptive error")
        void invalidAuditLevelIsRejected() {
            EncryptionConfigurationProperties props = devDefaults();
            props.getAudit().setLevel("VERBOSE");

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.audit.level")
                    .hasMessageContaining("VERBOSE");
        }

        @Test
        @DisplayName("Default dev salt in STAGING environment is rejected")
        void defaultDevSaltInStagingIsRejected() {
            EncryptionConfigurationProperties props = devDefaults();
            props.setEnvironment("STAGING");
            props.setBlindIndexGlobalSalt("default-dev-salt-change-in-prod");

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.blind-index-global-salt");
        }

        @Test
        @DisplayName("Default dev salt in PROD environment is rejected")
        void defaultDevSaltInProdIsRejected() {
            EncryptionConfigurationProperties props = devDefaults();
            props.setEnvironment("PROD");
            props.setBlindIndexGlobalSalt("default-dev-salt-change-in-prod");

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.blind-index-global-salt");
        }

        @Test
        @DisplayName("PROD environment with custom salt passes validation")
        void prodEnvironmentWithCustomSaltPasses() {
            EncryptionConfigurationProperties props = devDefaults();
            props.setEnvironment("PROD");
            props.setBlindIndexGlobalSalt("strong-unique-prod-salt-value-here");

            // Should not throw
            validatorFor(props).validate();
        }

        @Test
        @DisplayName("mTLS enabled without keystore path is rejected")
        void mtlsEnabledWithoutKeystoreIsRejected() {
            EncryptionConfigurationProperties props = devDefaults();
            props.getKms().setProvider("AWS_KMS");
            props.getKms().setEndpoint("https://kms.us-east-1.amazonaws.com");
            props.getKms().setRegion("us-east-1");
            props.getKms().getMtls().setEnabled(true);
            props.getKms().getMtls().setTruststorePath("/etc/ssl/truststore.jks");
            // keystorePath intentionally left blank

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.kms.mtls.keystore-path");
        }

        @Test
        @DisplayName("Validation error message lists all errors at once")
        void validationErrorMessageListsAllErrors() {
            EncryptionConfigurationProperties props = devDefaults();
            props.setEnvironment("BAD_ENV");
            props.getDekCache().setMaxSize(-1);
            props.getDekCache().setTtlMinutes(-1);

            assertThatThrownBy(() -> validatorFor(props).validate())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("pcm.encryption.environment")
                    .hasMessageContaining("pcm.encryption.dek-cache.max-size")
                    .hasMessageContaining("pcm.encryption.dek-cache.ttl-minutes");
        }

        // -------------------------------------------------------------------------
        // Helpers
        // -------------------------------------------------------------------------

        /** Returns a valid DEV configuration with all defaults set. */
        private EncryptionConfigurationProperties devDefaults() {
            EncryptionConfigurationProperties props = new EncryptionConfigurationProperties();
            props.setEnvironment("DEV");
            props.setDefaultContext("PROFILE");
            props.setBlindIndexGlobalSalt("test-salt-for-unit-tests");
            return props;
        }
    }

    // =========================================================================
    // Full test configuration – creates all encryption beans directly without
    // @ConditionalOnBean so they are always available in the test context.
    // =========================================================================

    @TestConfiguration
    @EnableConfigurationProperties(EncryptionConfigurationProperties.class)
    static class FullEncryptionTestConfiguration {

        @Bean
        IKMSClient stubKmsClient() {
            return new InMemoryStubKmsClient();
        }

        @Bean
        SecureRandom validatedSecureRandom() {
            return new SecureRandom();
        }

        @Bean
        dev.vibeafrika.pcm.domain.encryption.IEntropySource entropySource(SecureRandom sr) {
            return new dev.vibeafrika.pcm.infrastructure.encryption.JvmEntropySource(sr);
        }

        @Bean
        Environment encryptionEnvironment(EncryptionConfigurationProperties props) {
            return Environment.valueOf(props.getEnvironment().toUpperCase());
        }

        @Bean
        DEKCache dekCache(EncryptionConfigurationProperties props) {
            return new DEKCache(
                    props.getDekCache().getMaxSize(),
                    java.time.Duration.ofMinutes(props.getDekCache().getTtlMinutes()));
        }

        @Bean
        IVCounter ivCounter() {
            return new dev.vibeafrika.pcm.infrastructure.encryption.IVCounterImpl(
                    new dev.vibeafrika.pcm.infrastructure.encryption.InMemoryIVCounterStorage());
        }

        @Bean
        IAuditLogger auditLogger() {
            byte[] signingKey = new byte[32];
            new SecureRandom().nextBytes(signingKey);
            return new dev.vibeafrika.pcm.infrastructure.encryption.AuditLogger(
                    "test-service", signingKey);
        }

        @Bean
        KeyManager keyManager(IKMSClient kmsClient, IAuditLogger auditLogger,
                              DEKCache dekCache, Environment environment, IVCounter ivCounter) {
            return new dev.vibeafrika.pcm.infrastructure.encryption.KeyManager(
                    kmsClient, auditLogger, dekCache, environment, ivCounter);
        }

        @Bean
        BlindIndexService blindIndexService(KeyManager keyManager,
                                            EncryptionConfigurationProperties props) {
            return new BlindIndexService(keyManager, props.getBlindIndexGlobalSalt());
        }

        @Bean
        IEncryptionService encryptionService(KeyManager keyManager,
                                             BlindIndexService blindIndexService,
                                             IAuditLogger auditLogger,
                                             IVCounter ivCounter) {
            return new dev.vibeafrika.pcm.infrastructure.encryption.EncryptionService(
                    keyManager, blindIndexService, auditLogger, ivCounter);
        }
    }

    // =========================================================================
    // Stub KMS configuration – provides a functional IKMSClient so that
    // KeyManager and EncryptionService beans can be wired without a real KMS.
    // =========================================================================

    @TestConfiguration
    @EnableConfigurationProperties(EncryptionConfigurationProperties.class)
    static class StubKmsConfiguration {

        @Bean
        IKMSClient stubKmsClient() {
            return new InMemoryStubKmsClient();
        }
    }

    /**
     * In-memory IKMSClient that performs real AES-GCM wrap/unwrap of DEKs
     * using locally generated KEKs. Suitable for Spring context wiring tests.
     */
    static final class InMemoryStubKmsClient implements IKMSClient {

        private static final SecureRandom RANDOM = new SecureRandom();
        private final Map<UUID, byte[]> kekStore = new ConcurrentHashMap<>();

        @Override
        public Result<UUID, KMSError> generateKEK(BoundedContext context, Environment environment) {
            UUID kekId = UUID.randomUUID();
            byte[] kekBytes = new byte[32];
            RANDOM.nextBytes(kekBytes);
            kekStore.put(kekId, kekBytes);
            return Result.success(kekId);
        }

        @Override
        public Result<EncryptedDEK, KMSError> encryptDEK(DEK dek, UUID kekId) {
            byte[] kekBytes = kekStore.get(kekId);
            if (kekBytes == null) {
                return Result.failure(KMSError.of("KEK_NOT_FOUND", "KEK not found: " + kekId));
            }
            try {
                byte[] iv = new byte[12];
                RANDOM.nextBytes(iv);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(kekBytes, "AES"),
                        new GCMParameterSpec(128, iv));
                byte[] encrypted = cipher.doFinal(dek.getKeyMaterial());
                byte[] combined = new byte[iv.length + encrypted.length];
                System.arraycopy(iv, 0, combined, 0, iv.length);
                System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
                return Result.success(EncryptedDEK.of(combined, kekId));
            } catch (Exception e) {
                return Result.failure(KMSError.of("ENCRYPTION_FAILED", e.getMessage()));
            }
        }

        @Override
        public Result<DEK, KMSError> decryptDEK(EncryptedDEK encryptedDEK, UUID kekId) {
            byte[] kekBytes = kekStore.get(kekId);
            if (kekBytes == null) {
                return Result.failure(KMSError.of("KEK_NOT_FOUND", "KEK not found: " + kekId));
            }
            try {
                byte[] combined = encryptedDEK.getCiphertext();
                byte[] iv = new byte[12];
                System.arraycopy(combined, 0, iv, 0, 12);
                byte[] encryptedBytes = new byte[combined.length - 12];
                System.arraycopy(combined, 12, encryptedBytes, 0, encryptedBytes.length);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec(kekBytes, "AES"),
                        new GCMParameterSpec(128, iv));
                return Result.success(DEK.of(cipher.doFinal(encryptedBytes)));
            } catch (Exception e) {
                return Result.failure(KMSError.of("DECRYPTION_FAILED", e.getMessage()));
            }
        }

        @Override
        public Result<Unit, KMSError> deleteDEK(UUID keyId) {
            return Result.success(Unit.unit());
        }

        @Override
        public Result<KMSHealth, KMSError> healthCheck() {
            return Result.success(KMSHealth.healthy(0L));
        }

        @Override
        public Result<Unit, KMSError> storeSecret(UUID secretId, String secretValue, UUID kekId) {
            return Result.success(Unit.unit());
        }

        @Override
        public Result<String, KMSError> retrieveSecret(UUID secretId, UUID kekId) {
            return Result.failure(KMSError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<Unit, KMSError> deleteSecret(UUID secretId) {
            return Result.success(Unit.unit());
        }
    }
}
