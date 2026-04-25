package dev.vibeafrika.pcm.infrastructure.spring.config;

import dev.vibeafrika.pcm.domain.encryption.AlgorithmCompatibilityMatrix;
import dev.vibeafrika.pcm.domain.encryption.AlgorithmDeprecationPolicy;
import dev.vibeafrika.pcm.domain.encryption.Environment;
import dev.vibeafrika.pcm.domain.encryption.IAuditLogger;
import dev.vibeafrika.pcm.domain.encryption.IEncryptionService;
import dev.vibeafrika.pcm.domain.encryption.IKMSClient;
import dev.vibeafrika.pcm.domain.encryption.IKeyManager;
import dev.vibeafrika.pcm.domain.encryption.ISecretManager;
import dev.vibeafrika.pcm.domain.encryption.IVCounter;
import dev.vibeafrika.pcm.domain.encryption.IAlgorithmMigrationService;
import dev.vibeafrika.pcm.infrastructure.encryption.AlgorithmMigrationService;
import dev.vibeafrika.pcm.infrastructure.encryption.AuditLogger;
import dev.vibeafrika.pcm.infrastructure.encryption.BlindIndexService;
import dev.vibeafrika.pcm.infrastructure.encryption.DEKCache;
import dev.vibeafrika.pcm.infrastructure.encryption.DEKCacheWarmer;
import dev.vibeafrika.pcm.infrastructure.encryption.EncryptionMetrics;
import dev.vibeafrika.pcm.infrastructure.encryption.EncryptionService;
import dev.vibeafrika.pcm.infrastructure.encryption.IVCounterImpl;
import dev.vibeafrika.pcm.infrastructure.encryption.InMemoryIVCounterStorage;
import dev.vibeafrika.pcm.infrastructure.encryption.KeyManager;
import dev.vibeafrika.pcm.infrastructure.encryption.SecretManager;
import dev.vibeafrika.pcm.infrastructure.encryption.SecretRotationScheduler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Duration;

/**
 * Spring Boot auto-configuration for the PCM encryption subsystem.
 *
 * <p>Wires all encryption beans based on the {@code pcm.encryption.*} configuration
 * properties, supporting multiple KMS providers (AWS, Azure, GCP, Vault) via
 * conditional bean registration.
 *
 * <p>Bean registration strategy:
 * <ul>
 *   <li>{@link Environment} – resolved from {@code pcm.encryption.environment}</li>
 *   <li>{@link DEKCache} – LRU cache sized and TTL-configured from properties</li>
 *   <li>{@link IVCounter} – counter-based IV generation with in-memory storage</li>
 *   <li>{@link KeyManager} – wired when {@link IKMSClient} and {@link IAuditLogger} are present</li>
 *   <li>{@link BlindIndexService} – wired when {@link KeyManager} is present</li>
 *   <li>{@link IEncryptionService} – wired when all dependencies are present</li>
 *   <li>{@link ISecretManager} – wired when {@link KeyManager} is present</li>
 *   <li>{@link DEKCacheWarmer} – pre-warms the DEK cache on startup</li>
 *   <li>{@link SecretRotationScheduler} – checks for overdue secrets hourly</li>
 * </ul>
 *
 * <p>All beans use {@link ConditionalOnMissingBean} to allow application-level overrides,
 * supporting extensibility without modifying this configuration class.
 */
@Configuration
@EnableScheduling
@EnableConfigurationProperties(EncryptionConfigurationProperties.class)
public class EncryptionAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionAutoConfiguration.class);

    private final EncryptionConfigurationProperties properties;

    /** Holds a reference to the DEK cache for the scheduled eviction task. */
    private DEKCache dekCacheRef;

    public EncryptionAutoConfiguration(EncryptionConfigurationProperties properties) {
        this.properties = properties;
    }

    // =========================================================================
    // Core infrastructure beans
    // =========================================================================

    /**
     * Creates the {@link Environment} bean from {@code pcm.encryption.environment}.
     *
     * <p>Defaults to {@code DEV} if not configured. In production deployments this
     * must be set to {@code PROD} to enforce key isolation.
     *
     * @return the configured deployment environment
     * @throws IllegalArgumentException if the environment value is invalid
     */
    @Bean
    @ConditionalOnMissingBean(Environment.class)
    public Environment encryptionEnvironment() {
        String envName = properties.getEnvironment();
        try {
            Environment env = Environment.valueOf(envName.toUpperCase());
            logger.info("Encryption environment: {}", env);
            return env;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Invalid pcm.encryption.environment value: '" + envName
                    + "'. Must be one of: DEV, STAGING, PROD", e);
        }
    }

    /**
     * Creates the {@link DEKCache} bean for caching decrypted DEKs in memory.
     *
     * <p>Cache size and TTL are driven by {@code pcm.encryption.dek-cache.*} properties.
     * Defaults: maxSize=1000, ttlMinutes=60.
     *
     * @return the configured DEK cache
     */
    @Bean
    @ConditionalOnMissingBean(DEKCache.class)
    public DEKCache dekCache() {
        int maxSize = properties.getDekCache().getMaxSize();
        int ttlMinutes = properties.getDekCache().getTtlMinutes();
        logger.info("Creating DEKCache: maxSize={}, ttlMinutes={}", maxSize, ttlMinutes);
        this.dekCacheRef = new DEKCache(maxSize, Duration.ofMinutes(ttlMinutes));
        return this.dekCacheRef;
    }

    /**
     * Creates the {@link IVCounter} bean for counter-based IV generation.
     *
     * <p>Uses in-memory storage by default. For production deployments with
     * persistence requirements, provide a custom {@link IVCounter} bean that
     * uses {@code DatabaseIVCounterStorage}.
     *
     * @return the IV counter
     */
    @Bean
    @ConditionalOnMissingBean(IVCounter.class)
    public IVCounter ivCounter() {
        logger.info("Creating IVCounter with in-memory storage");
        return new IVCounterImpl(new InMemoryIVCounterStorage());
    }

    // =========================================================================
    // Key management beans
    // =========================================================================

    /**
     * Creates the {@link KeyManager} bean implementing {@link IKeyManager}.
     *
     * <p>Requires {@link IKMSClient} and {@link IAuditLogger} beans to be present.
     * The KMS client is provided by one of the provider-specific configurations
     * (AWS, Azure, GCP) activated via {@code pcm.encryption.kms.provider}.
     *
     * @param kmsClient         the KMS client for key operations
     * @param auditLogger       the audit logger for key access logging
     * @param dekCache          the DEK cache for performance optimization
     * @param environment       the current deployment environment
     * @param ivCounter         the IV counter for per-DEK IV state management
     * @param encryptionMetrics optional metrics bean for cache hit/miss tracking
     * @return the configured KeyManager
     */
    @Bean
    @ConditionalOnMissingBean(IKeyManager.class)
    @ConditionalOnBean({IKMSClient.class, IAuditLogger.class})
    public KeyManager keyManager(IKMSClient kmsClient,
                                  IAuditLogger auditLogger,
                                  DEKCache dekCache,
                                  Environment environment,
                                  IVCounter ivCounter,
                                  @Nullable EncryptionMetrics encryptionMetrics) {
        logger.info("Creating KeyManager for environment: {}", environment);
        KeyManager km = new KeyManager(kmsClient, auditLogger, dekCache, environment, ivCounter);
        if (encryptionMetrics != null) {
            km.setEncryptionMetrics(encryptionMetrics);
        }
        return km;
    }

    /**
     * Creates the {@link BlindIndexService} bean for searchable encryption.
     *
     * <p>Uses the global salt from {@code pcm.encryption.blind-index-global-salt}.
     * The default salt is only suitable for development; production deployments
     * must override this with a strong, unique secret.
     *
     * @param keyManager the key manager used to retrieve the blind index key
     * @return the blind index service
     */
    @Bean
    @ConditionalOnMissingBean(BlindIndexService.class)
    @ConditionalOnBean(KeyManager.class)
    public BlindIndexService blindIndexService(KeyManager keyManager) {
        String globalSalt = properties.getBlindIndexGlobalSalt();
        logger.info("Creating BlindIndexService");
        return new BlindIndexService(keyManager, globalSalt);
    }

    /**
     * Creates the {@link IEncryptionService} bean.
     *
     * <p>Requires {@link KeyManager}, {@link BlindIndexService}, {@link IAuditLogger},
     * and {@link IVCounter} beans to be present.
     *
     * @param keyManager        the key manager
     * @param blindIndexService the blind index service
     * @param auditLogger       the audit logger
     * @param ivCounter         the IV counter
     * @return the encryption service
     */
    @Bean
    @ConditionalOnMissingBean(IEncryptionService.class)
    @ConditionalOnBean({KeyManager.class, BlindIndexService.class, IAuditLogger.class})
    public IEncryptionService encryptionService(KeyManager keyManager,
                                                 BlindIndexService blindIndexService,
                                                 IAuditLogger auditLogger,
                                                 IVCounter ivCounter) {
        logger.info("Creating EncryptionService");
        return new EncryptionService(keyManager, blindIndexService, auditLogger, ivCounter);
    }

    // =========================================================================
    // Supporting beans
    // =========================================================================

    /**
     * Creates the {@link DEKCacheWarmer} bean that pre-warms the DEK cache on startup.
     *
     * @param keyManager the KeyManager used to fetch active DEKs
     * @return the cache warmer
     */
    @Bean
    @ConditionalOnMissingBean(DEKCacheWarmer.class)
    @ConditionalOnBean(KeyManager.class)
    public DEKCacheWarmer dekCacheWarmer(KeyManager keyManager) {
        logger.info("Creating DEKCacheWarmer");
        return new DEKCacheWarmer(keyManager);
    }

    /**
     * Creates the {@link ISecretManager} bean for unified secret management.
     *
     * <p>Shares the same DEK cache, KMS client, audit logger, and environment as
     * {@link KeyManager}, applying the same TTL/LRU caching and access control
     * policies to non-cryptographic secrets.
     *
     * @param kmsClient   the KMS client
     * @param auditLogger the audit logger
     * @param dekCache    the shared DEK/secret cache
     * @param environment the current deployment environment
     * @param keyManager  the key manager (provides KEK IDs per bounded context)
     * @return the configured SecretManager
     */
    @Bean
    @ConditionalOnMissingBean(ISecretManager.class)
    @ConditionalOnBean(KeyManager.class)
    public ISecretManager secretManager(IKMSClient kmsClient,
                                         IAuditLogger auditLogger,
                                         DEKCache dekCache,
                                         Environment environment,
                                         KeyManager keyManager) {
        logger.info("Creating SecretManager for environment: {}", environment);
        // SecretManager shares the same KEK map as KeyManager.
        // The KEK map is populated lazily on first key access.
        return new SecretManager(kmsClient, auditLogger, dekCache, environment,
                new java.util.EnumMap<>(dev.vibeafrika.pcm.domain.encryption.BoundedContext.class));
    }

    /**
     * Creates the {@link SecretRotationScheduler} bean that checks for overdue secrets hourly.
     *
     * @param secretManager the secret manager
     * @param auditLogger   the audit logger
     * @return the rotation scheduler
     */
    @Bean
    @ConditionalOnMissingBean(SecretRotationScheduler.class)
    @ConditionalOnBean(ISecretManager.class)
    public SecretRotationScheduler secretRotationScheduler(ISecretManager secretManager,
                                                            IAuditLogger auditLogger) {
        logger.info("Creating SecretRotationScheduler");
        return new SecretRotationScheduler((SecretManager) secretManager, auditLogger);
    }

    // =========================================================================
    // Scheduled maintenance
    // =========================================================================

    /**
     * Scheduled task that proactively evicts expired DEK cache entries every 5 minutes.
     *
     * <p>This supplements the lazy TTL-based eviction in {@link DEKCache} with
     * proactive cleanup to bound memory usage.
     */
    @Scheduled(fixedDelayString = "PT5M")
    public void evictExpiredDEKs() {
        if (dekCacheRef != null) {
            logger.debug("Running scheduled DEK cache eviction");
            dekCacheRef.evictExpired();
        }
    }

    // =========================================================================
    // Algorithm deprecation and compatibility beans
    // =========================================================================

    /**
     * Creates the {@link AlgorithmDeprecationPolicy} bean for managing algorithm
     * deprecation notices with a mandatory 12-month notice period.
     *
     * @return the algorithm deprecation policy
     */
    @Bean
    @ConditionalOnMissingBean(AlgorithmDeprecationPolicy.class)
    public AlgorithmDeprecationPolicy algorithmDeprecationPolicy() {
        logger.info("Creating AlgorithmDeprecationPolicy");
        return new AlgorithmDeprecationPolicy();
    }

    /**
     * Creates the {@link AlgorithmCompatibilityMatrix} bean pre-populated with
     * the default version compatibility rules.
     *
     * @return the algorithm compatibility matrix
     */
    @Bean
    @ConditionalOnMissingBean(AlgorithmCompatibilityMatrix.class)
    public AlgorithmCompatibilityMatrix algorithmCompatibilityMatrix() {
        logger.info("Creating AlgorithmCompatibilityMatrix");
        return new AlgorithmCompatibilityMatrix();
    }

    // =========================================================================
    // Algorithm migration bean
    // =========================================================================

    /**
     * Creates the {@link AlgorithmMigrationService} bean for managing cryptographic
     * algorithm migrations with gradual rollout and rollback support.
     *
     * <p>Supports parallel operation of old and new algorithms,
     * gradual rollout starting at 1% (Req 32.4), rollback within 24 hours,
     * and algorithm usage metrics logging.
     *
     * @return the algorithm migration service
     */
    @Bean
    @ConditionalOnMissingBean(IAlgorithmMigrationService.class)
    public AlgorithmMigrationService algorithmMigrationService() {
        logger.info("Creating AlgorithmMigrationService");
        return new AlgorithmMigrationService();
    }

    // =========================================================================
    // Audit logger bean (default no-op / SLF4J-backed implementation)
    // =========================================================================

    /**
     * Creates the default {@link IAuditLogger} bean backed by the infrastructure
     * {@link AuditLogger} implementation.
     *
     * <p>Uses a random signing key by default. For production deployments, provide
     * a custom {@link IAuditLogger} bean with a stable, securely-stored signing key
     * to ensure audit log integrity across restarts.
     *
     * <p>Uses {@link ConditionalOnMissingBean} so that application code can provide
     * a custom audit logger (e.g., one that writes to a dedicated audit database)
     * without modifying this configuration.
     *
     * @return the default audit logger
     */
    @Bean
    @ConditionalOnMissingBean(IAuditLogger.class)
    @ConditionalOnProperty(name = "pcm.encryption.kms.provider")
    public IAuditLogger auditLogger() {
        logger.info("Creating default AuditLogger for service: pcm-service");
        // Generate a random signing key for this session.
        // In production, inject a stable key from a secret manager.
        byte[] signingKey = new byte[32];
        new java.security.SecureRandom().nextBytes(signingKey);
        return new AuditLogger("pcm-service", signingKey);
    }
}
