package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.context.event.ApplicationReadyEvent;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link DEKCacheWarmer}.
 *
 * <p>Verifies:
 * <ul>
 *   <li>Cache is pre-warmed for all bounded contexts on startup</li>
 *   <li>Warming failures do not throw exceptions (startup safety)</li>
 *   <li>Cache hit rate is tracked via {@link EncryptionMetrics} after warming</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class DEKCacheWarmingTest {

    @Mock
    private IKMSClient kmsClient;

    @Mock
    private IAuditLogger auditLogger;

    @Mock
    private IVCounter ivCounter;

    @Mock
    private ApplicationReadyEvent applicationReadyEvent;

    private DEKCache dekCache;
    private KeyManager keyManager;
    private EncryptionMetrics encryptionMetrics;

    private static final Environment ENV = Environment.DEV;
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeEach
    void setUp() {
        dekCache = new DEKCache(1000, java.time.Duration.ofHours(1));
        keyManager = new KeyManager(kmsClient, auditLogger, dekCache, ENV, ivCounter);

        AuditError noopError = AuditError.of("NOOP", "no-op");
        lenient().when(auditLogger.logKeyAccess(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logKeyRotation(any())).thenReturn(Result.failure(noopError));
        lenient().when(auditLogger.logSecurityEvent(any())).thenReturn(Result.failure(noopError));
        lenient().when(ivCounter.resetState(any())).thenReturn(Result.success(Unit.unit()));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    private EncryptedDEK fakeEncryptedDEK(UUID kekId) {
        return EncryptedDEK.of(randomBytes(48), kekId);
    }

    /** Initialises a KEK + one active DEK for the given context. */
    private void setupContext(BoundedContext context) {
        UUID kekId = UUID.randomUUID();
        when(kmsClient.generateKEK(context, ENV)).thenReturn(Result.success(kekId));
        keyManager.initializeKEK(context);

        when(kmsClient.encryptDEK(any(DEK.class), eq(kekId)))
                .thenReturn(Result.success(fakeEncryptedDEK(kekId)));
        keyManager.rotateDEK(context);

        // Stub decryptDEK so getActiveDEK (cache-miss path) succeeds
        DEK plainDEK = DEK.of(randomBytes(32));
        when(kmsClient.decryptDEK(any(EncryptedDEK.class), eq(kekId)))
                .thenReturn(Result.success(plainDEK));
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Warmer pre-warms cache for all bounded contexts that have an active DEK")
    void warmer_preWarmsAllContexts() {
        for (BoundedContext ctx : BoundedContext.values()) {
            setupContext(ctx);
        }

        // Cache should be empty before warming
        assertEquals(0, dekCache.size(), "Cache should be empty before warming");

        DEKCacheWarmer warmer = new DEKCacheWarmer(keyManager);
        warmer.onApplicationEvent(applicationReadyEvent);

        // After warming, each context's active DEK should be in the cache
        assertEquals(BoundedContext.values().length, dekCache.size(),
                "Cache should contain one entry per bounded context after warming");
    }

    @Test
    @DisplayName("Warmer does not throw when a context has no active DEK")
    void warmer_doesNotThrowOnMissingDEK() {
        // No contexts initialised — getActiveDEK returns KEY_NOT_FOUND for all
        DEKCacheWarmer warmer = new DEKCacheWarmer(keyManager);

        assertDoesNotThrow(() -> warmer.onApplicationEvent(applicationReadyEvent),
                "Cache warming must not throw even when no active DEKs exist");
    }

    @Test
    @DisplayName("Warmer does not throw when getActiveDEK raises an unexpected exception")
    void warmer_doesNotThrowOnException() {
        KeyManager failingKeyManager = mock(KeyManager.class);
        when(failingKeyManager.getActiveDEK(any()))
                .thenThrow(new RuntimeException("Simulated KMS outage"));

        DEKCacheWarmer warmer = new DEKCacheWarmer(failingKeyManager);

        assertDoesNotThrow(() -> warmer.onApplicationEvent(applicationReadyEvent),
                "Cache warming must not propagate unexpected exceptions");
    }

    @Test
    @DisplayName("Cache hit rate is tracked via EncryptionMetrics after warming and subsequent access")
    void metrics_cacheHitRateTrackedAfterWarming() {
        // Wire metrics into KeyManager
        encryptionMetrics = new EncryptionMetrics(new SimpleMeterRegistry());
        keyManager.setEncryptionMetrics(encryptionMetrics);

        // Set up one context
        BoundedContext ctx = BoundedContext.PROFILE;
        setupContext(ctx);

        // Warm the cache — this triggers a cache miss (DEK fetched from KMS)
        DEKCacheWarmer warmer = new DEKCacheWarmer(keyManager);
        warmer.onApplicationEvent(applicationReadyEvent);

        // Access the same DEK again — should be a cache hit now
        keyManager.getActiveDEK(ctx);

        double hitRate = encryptionMetrics.getCacheHitRate();
        assertTrue(hitRate > 0.0,
                "Cache hit rate should be > 0 after at least one cache hit");
    }

    @Test
    @DisplayName("DEKCache is configurable via constructor parameters")
    void dekCache_configurableViaCtor() {
        DEKCache smallCache = new DEKCache(10, java.time.Duration.ofMinutes(5));
        assertNotNull(smallCache);

        // Fill to capacity
        for (int i = 0; i < 10; i++) {
            UUID id = UUID.randomUUID();
            DEKWithMetadata dek = DEKWithMetadata.builder()
                    .dek(DEK.of(randomBytes(32)))
                    .keyId(id)
                    .kekId(UUID.randomUUID())
                    .context(BoundedContext.PROFILE)
                    .environment(ENV)
                    .algorithm(EncryptionAlgorithm.AES_256_GCM)
                    .createdAt(Instant.now())
                    .status(KeyStatus.ACTIVE)
                    .encryptionCount(0)
                    .bytesEncrypted(0)
                    .build();
            smallCache.put(id, dek);
        }
        assertEquals(10, smallCache.size(), "Cache should hold exactly 10 entries");

        // One more entry triggers LRU eviction
        UUID extraId = UUID.randomUUID();
        smallCache.put(extraId, DEKWithMetadata.builder()
                .dek(DEK.of(randomBytes(32)))
                .keyId(extraId)
                .kekId(UUID.randomUUID())
                .context(BoundedContext.PROFILE)
                .environment(ENV)
                .algorithm(EncryptionAlgorithm.AES_256_GCM)
                .createdAt(Instant.now())
                .status(KeyStatus.ACTIVE)
                .encryptionCount(0)
                .bytesEncrypted(0)
                .build());

        assertTrue(smallCache.size() <= 10, "Cache size must not exceed configured max");
    }
}
