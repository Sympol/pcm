package dev.vibeafrika.pcm.infrastructure.spring.config;

import dev.vibeafrika.pcm.domain.encryption.Environment;
import dev.vibeafrika.pcm.domain.encryption.IAuditLogger;
import dev.vibeafrika.pcm.domain.encryption.IEncryptionService;
import dev.vibeafrika.pcm.domain.encryption.IKMSClient;
import dev.vibeafrika.pcm.domain.encryption.ISecretManager;
import dev.vibeafrika.pcm.domain.encryption.IVCounter;
import dev.vibeafrika.pcm.infrastructure.encryption.BlindIndexService;
import dev.vibeafrika.pcm.infrastructure.encryption.DEKCache;
import dev.vibeafrika.pcm.infrastructure.encryption.DEKCacheWarmer;
import dev.vibeafrika.pcm.infrastructure.encryption.EncryptionMetrics;
import dev.vibeafrika.pcm.infrastructure.encryption.EncryptionService;
import dev.vibeafrika.pcm.infrastructure.encryption.HardwareAccelerationConfig;
import dev.vibeafrika.pcm.infrastructure.encryption.IVCounterImpl;
import dev.vibeafrika.pcm.infrastructure.encryption.InMemoryIVCounterStorage;
import dev.vibeafrika.pcm.infrastructure.encryption.KeyManager;
import dev.vibeafrika.pcm.infrastructure.encryption.SecretManager;
import dev.vibeafrika.pcm.infrastructure.encryption.SecretRotationScheduler;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Spring configuration for the encryption infrastructure.
 *
 * <p>Wires the {@link KeyManager} with environment-specific configuration,
 * ensuring that each environment (DEV, STAGING, PROD) uses separate root KEKs
 * and isolated KMS namespaces (Requirements 17.1, 17.2, 17.3, 17.4).
 *
 * <p>The environment is injected via the {@code encryption.environment} property,
 * defaulting to {@code DEV} if not specified. In production deployments, this
 * must be set to {@code PROD} to enforce production key isolation.
 *
 * <p>Example configuration:
 * <pre>
 * encryption:
 *   environment: PROD
 *   kms:
 *     provider: AWS_KMS
 * </pre>
 */
@Configuration
@EnableScheduling
public class EncryptionConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionConfiguration.class);

    /**
     * The deployment environment for key isolation.
     * Defaults to DEV if not configured.
     */
    @Value("${encryption.environment:DEV}")
    private String environmentName;

    /** Maximum number of DEKs to hold in the LRU cache. */
    @Value("${encryption.dek-cache.max-size:1000}")
    private int dekCacheMaxSize;

    /** Time-to-live for cached DEKs, in minutes. */
    @Value("${encryption.dek-cache.ttl-minutes:60}")
    private int dekCacheTtlMinutes;

    /** Secret global salt for blind index generation (resists frequency analysis). */
    @Value("${encryption.blind-index.global-salt:default-dev-salt-change-in-prod}")
    private String blindIndexGlobalSalt;

    /** The DEK cache bean — set when the bean is created, used for the scheduled eviction task. */
    private DEKCache dekCache;

    /**
     * Validates hardware acceleration availability at startup.
     *
     * <p>Logs whether AES-NI acceleration is likely in use. This is informational only —
     * AES-NI is an optimization; startup is not blocked if it is unavailable (Requirement 10.9).
     */
    @PostConstruct
    public void validateHardwareAcceleration() {
        boolean aesNiAvailable = HardwareAccelerationConfig.isAesNiAvailable();
        logger.info("AES-NI hardware acceleration: {}", aesNiAvailable ? "available" : "not detected");
    }

    /**
     * Creates the {@link Environment} bean from the configured environment name.
     *
     * <p>This bean is used by {@link KeyManager} to namespace all keys under
     * the correct environment, preventing cross-environment key reuse.
     *
     * @return the configured environment
     * @throws IllegalArgumentException if the environment name is invalid
     */
    @Bean
    @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(Environment.class)
    public Environment encryptionEnvironment() {
        try {
            Environment env = Environment.valueOf(environmentName.toUpperCase());
            logger.info("Encryption environment configured: {}", env);
            return env;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Invalid encryption.environment value: '" + environmentName +
                "'. Must be one of: DEV, STAGING, PROD", e
            );
        }
    }

    /**
     * Creates the {@link DEKCache} bean for caching decrypted DEKs.
     * Size and TTL are configurable via {@code encryption.dek-cache.max-size}
     * and {@code encryption.dek-cache.ttl-minutes}.
     *
     * @return the DEK cache
     */
    @Bean
    @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(DEKCache.class)
    public DEKCache dekCache() {
        logger.info("Creating DEKCache: maxSize={}, ttlMinutes={}", dekCacheMaxSize, dekCacheTtlMinutes);
        this.dekCache = new DEKCache(dekCacheMaxSize, java.time.Duration.ofMinutes(dekCacheTtlMinutes));
        return this.dekCache;
    }

    /**
     * Creates the {@link IVCounter} bean for counter-based IV generation.
     *
     * @return the IV counter
     */
    @Bean
    @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(IVCounter.class)
    public IVCounter ivCounter() {
        return new IVCounterImpl(new InMemoryIVCounterStorage());
    }

    /**
     * Creates the {@link KeyManager} bean with environment-specific configuration.
     *
     * <p>The KeyManager is configured with the current environment to ensure:
     * <ul>
     *   <li>All generated keys are namespaced under the current environment</li>
     *   <li>Keys from other environments are rejected (environment mismatch detection)</li>
     *   <li>Separate KMS namespaces are used per environment</li>
     * </ul>
     *
     * @param kmsClient          the KMS client for key operations
     * @param auditLogger        the audit logger for key access logging
     * @param dekCache           the DEK cache for performance optimization
     * @param environment        the current deployment environment
     * @param ivCounter          the IV counter for per-DEK IV state management
     * @param encryptionMetrics  optional metrics bean for cache hit/miss tracking
     * @return the configured KeyManager
     */
    @Bean
    @ConditionalOnBean({IKMSClient.class, IAuditLogger.class})
    @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(KeyManager.class)
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
     * @param keyManager the key manager used to retrieve the blind index key
     * @return the blind index service
     */
    @Bean
    @ConditionalOnBean(KeyManager.class)
    @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(BlindIndexService.class)
    public BlindIndexService blindIndexService(KeyManager keyManager) {
        logger.info("Creating BlindIndexService");
        return new BlindIndexService(keyManager, blindIndexGlobalSalt);
    }

    /**
     * Creates the {@link EncryptionService} bean implementing {@link IEncryptionService}.
     *
     * @param keyManager       the key manager
     * @param blindIndexService the blind index service
     * @param auditLogger      the audit logger
     * @param ivCounter        the IV counter
     * @return the encryption service
     */
    @Bean
    @ConditionalOnBean({KeyManager.class, BlindIndexService.class, IAuditLogger.class})
    @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(IEncryptionService.class)
    public IEncryptionService encryptionService(KeyManager keyManager,
                                                 BlindIndexService blindIndexService,
                                                 IAuditLogger auditLogger,
                                                 IVCounter ivCounter) {
        logger.info("Creating EncryptionService");
        return new EncryptionService(keyManager, blindIndexService, auditLogger, ivCounter);
    }

    /**
     * Creates the {@link DEKCacheWarmer} bean that pre-warms the DEK cache on startup.
     *
     * @param keyManager the KeyManager used to fetch active DEKs
     * @return the cache warmer
     */
    @Bean
    @ConditionalOnBean(KeyManager.class)
    @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(DEKCacheWarmer.class)
    public DEKCacheWarmer dekCacheWarmer(KeyManager keyManager) {
        return new DEKCacheWarmer(keyManager);
    }

    /**
     * Creates the {@link SecretManager} bean for unified secret management.
     *
     * <p>Shares the same DEK cache, KMS client, audit logger, and environment as
     * {@link KeyManager}, applying the same TTL/LRU caching and access control
     * policies to non-cryptographic secrets (Requirements 36.8, 36.9).
     *
     * @param kmsClient   the KMS client
     * @param auditLogger the audit logger
     * @param dekCache    the shared DEK/secret cache
     * @param environment the current deployment environment
     * @param keyManager  the key manager (provides KEK IDs per bounded context)
     * @return the configured SecretManager
     */
    @Bean
    @ConditionalOnBean(KeyManager.class)
    @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(ISecretManager.class)
    public ISecretManager secretManager(IKMSClient kmsClient,
                                         IAuditLogger auditLogger,
                                         DEKCache dekCache,
                                         Environment environment,
                                         KeyManager keyManager) {
        logger.info("Creating SecretManager for environment: {}", environment);
        return new SecretManager(kmsClient, auditLogger, dekCache, environment, keyManager.getKekIds());
    }

    /**
     * Creates the {@link SecretRotationScheduler} bean that checks for overdue secrets hourly.
     *
     * @param secretManager the secret manager
     * @param auditLogger   the audit logger
     * @return the rotation scheduler
     */
    @Bean
    @ConditionalOnBean(ISecretManager.class)
    @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(SecretRotationScheduler.class)
    public SecretRotationScheduler secretRotationScheduler(ISecretManager secretManager,
                                                            IAuditLogger auditLogger) {
        logger.info("Creating SecretRotationScheduler");
        return new SecretRotationScheduler((SecretManager) secretManager, auditLogger);
    }

    /**
     * Scheduled task that proactively evicts expired DEK cache entries every 5 minutes.
     */
    @Scheduled(fixedDelayString = "PT5M")
    public void evictExpiredDEKs() {
        logger.debug("Running scheduled DEK cache eviction");
        dekCache.evictExpired();
    }
}
