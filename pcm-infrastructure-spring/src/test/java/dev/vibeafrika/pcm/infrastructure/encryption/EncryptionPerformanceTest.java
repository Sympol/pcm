package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Performance tests for the PII encryption subsystem.
 *
 * <p>Validates :
 * <ul>
 *   <li>Single field encrypt/decrypt with local DEK caching: p95 &lt; 10 ms</li>
 *   <li>Batch throughput: ≥ 100 fields/second</li>
 *   <li>DEK cache hit rate: ≥ 90 %</li>
 * </ul>
 *
 * <p>Uses plain JUnit timing ({@link System#nanoTime()}) — no JMH required.
 * Each latency test collects N=100 samples after a warm-up phase to avoid
 * JIT-compilation skew.
 */
@DisplayName("Encryption Performance Tests")
class EncryptionPerformanceTest {

    private static final Logger log = LoggerFactory.getLogger(EncryptionPerformanceTest.class);

    // ── Thresholds ────────────────────────────────────────────────────────────
    /** Validates p95 latency with local DEK caching. */
    private static final long LATENCY_P95_THRESHOLD_MS = 10L;
    /** Validates minimum batch throughput. */
    private static final int  BATCH_MIN_FIELDS_PER_SECOND = 100;
    /** Validates minimum DEK cache hit rate. */
    private static final double CACHE_HIT_RATE_THRESHOLD = 0.90;

    // ── Sample sizes ──────────────────────────────────────────────────────────
    private static final int WARMUP_COUNT  = 20;
    private static final int MEASURE_COUNT = 100;

    // ── Shared test infrastructure (stub-based, no real KMS) ─────────────────
    private EncryptionService encryptionService;
    private BlindIndexService blindIndexService;
    private StubKeyManager    stubKeyManager;

    @BeforeEach
    void setUp() {
        UUID dekId = UUID.randomUUID();
        stubKeyManager   = new StubKeyManager(dekId);
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        blindIndexService   = new BlindIndexService(stubKeyManager, "perf-test-global-salt");
        NoOpAuditLogger auditLogger = new NoOpAuditLogger();
        encryptionService   = new EncryptionService(stubKeyManager, blindIndexService, auditLogger, ivCounter);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /** Returns the p-th percentile (1-100) of a pre-sorted sample list (nanoseconds → ms). */
    private long percentileMs(List<Long> sortedNanos, int p) {
        if (sortedNanos.isEmpty()) return 0L;
        int index = (int) Math.ceil(p / 100.0 * sortedNanos.size()) - 1;
        index = Math.max(0, Math.min(index, sortedNanos.size() - 1));
        return sortedNanos.get(index) / 1_000_000L;
    }

    private void logLatencyStats(String label, List<Long> sortedNanos) {
        log.info("[Perf] {} — p50={}ms  p95={}ms  p99={}ms  (n={})",
                label,
                percentileMs(sortedNanos, 50),
                percentileMs(sortedNanos, 95),
                percentileMs(sortedNanos, 99),
                sortedNanos.size());
    }

    // =========================================================================
    // 1. Encryption latency < 10 ms with caching
    // =========================================================================

    @Nested
    @DisplayName("Encryption latency with DEK caching")
    class EncryptionLatencyTests {

        /**
         * Validates: 
         *
         * <p>Warm up the DEK cache first (WARMUP_COUNT encryptions), then measure
         * MEASURE_COUNT individual encrypt() calls and assert p95 &lt; 10 ms.
         */
        @Test
        @DisplayName("p95 encryption latency is under 10ms with warm DEK cache")
        void encryptionLatency_p95_underThreshold_withWarmCache() {
            // Warm up – populate DEK cache and trigger JIT compilation
            for (int i = 0; i < WARMUP_COUNT; i++) {
                Result<Ciphertext, EncryptionError> r =
                        encryptionService.encrypt("warmup-" + i + "@example.com", BoundedContext.PROFILE);
                assertTrue(r.isSuccess(), "Warm-up encryption must succeed");
            }

            // Measure
            List<Long> samples = new ArrayList<>(MEASURE_COUNT);
            for (int i = 0; i < MEASURE_COUNT; i++) {
                long start = System.nanoTime();
                Result<Ciphertext, EncryptionError> result =
                        encryptionService.encrypt("user-" + i + "@example.com", BoundedContext.PROFILE);
                long elapsed = System.nanoTime() - start;
                assertTrue(result.isSuccess(), "Encryption must succeed during measurement");
                samples.add(elapsed);
            }

            samples.sort(Long::compareTo);
            logLatencyStats("encrypt() with warm cache", samples);

            long p95Ms = percentileMs(samples, 95);
            assertTrue(p95Ms < LATENCY_P95_THRESHOLD_MS,
                    String.format("Encryption p95 latency %dms exceeds threshold of %dms (Req 10.1)",
                            p95Ms, LATENCY_P95_THRESHOLD_MS));
        }
    }

    // =========================================================================
    // Decryption latency < 10 ms with caching 
    // =========================================================================

    @Nested
    @DisplayName("Decryption latency with DEK caching")
    class DecryptionLatencyTests {

        /**
         * Validates: 
         *
         * <p>Pre-encrypt data to populate the DEK cache, then measure MEASURE_COUNT
         * individual decrypt() calls and assert p95 &lt; 10 ms.
         */
        @Test
        @DisplayName("p95 decryption latency is under 10ms with warm DEK cache")
        void decryptionLatency_p95_underThreshold_withWarmCache() {
            // Pre-encrypt to populate cache and collect ciphertexts
            List<Ciphertext> ciphertexts = new ArrayList<>(WARMUP_COUNT + MEASURE_COUNT);
            for (int i = 0; i < WARMUP_COUNT + MEASURE_COUNT; i++) {
                Result<Ciphertext, EncryptionError> r =
                        encryptionService.encrypt("user-" + i + "@example.com", BoundedContext.PROFILE);
                assertTrue(r.isSuccess(), "Pre-encryption must succeed");
                ciphertexts.add(r.getValue().orElseThrow());
            }

            // Warm up decryption path
            for (int i = 0; i < WARMUP_COUNT; i++) {
                Result<String, DecryptionError> r =
                        encryptionService.decrypt(ciphertexts.get(i), BoundedContext.PROFILE);
                assertTrue(r.isSuccess(), "Warm-up decryption must succeed");
            }

            // Measure
            List<Long> samples = new ArrayList<>(MEASURE_COUNT);
            for (int i = WARMUP_COUNT; i < WARMUP_COUNT + MEASURE_COUNT; i++) {
                long start = System.nanoTime();
                Result<String, DecryptionError> result =
                        encryptionService.decrypt(ciphertexts.get(i), BoundedContext.PROFILE);
                long elapsed = System.nanoTime() - start;
                assertTrue(result.isSuccess(), "Decryption must succeed during measurement");
                samples.add(elapsed);
            }

            samples.sort(Long::compareTo);
            logLatencyStats("decrypt() with warm cache", samples);

            long p95Ms = percentileMs(samples, 95);
            assertTrue(p95Ms < LATENCY_P95_THRESHOLD_MS,
                    String.format("Decryption p95 latency %dms exceeds threshold of %dms (Req 10.1)",
                            p95Ms, LATENCY_P95_THRESHOLD_MS));
        }
    }

    // =========================================================================
    // Batch throughput > 100 fields/second
    // =========================================================================

    @Nested
    @DisplayName("Batch throughput")
    class BatchThroughputTests {

        /**
         * Validates:
         *
         * <p>Prepare 200+ plaintext strings, time the encryptBatch() call, and assert
         * throughput ≥ 100 fields/second.
         */
        @Test
        @DisplayName("encryptBatch achieves at least 100 fields per second")
        void encryptBatch_throughput_meetsMinimum() {
            int batchSize = 200;
            List<String> plaintexts = new ArrayList<>(batchSize);
            for (int i = 0; i < batchSize; i++) {
                plaintexts.add("user-" + i + "@example.com");
            }

            // Warm up
            encryptionService.encryptBatch(plaintexts.subList(0, 10), BoundedContext.PROFILE);

            // Measure
            long startNs = System.nanoTime();
            Result<List<Ciphertext>, EncryptionError> result =
                    encryptionService.encryptBatch(plaintexts, BoundedContext.PROFILE);
            long elapsedMs = (System.nanoTime() - startNs) / 1_000_000L;

            assertTrue(result.isSuccess(), "Batch encryption must succeed");
            assertEquals(batchSize, result.getValue().orElseThrow().size(),
                    "All fields must be encrypted");

            double fieldsPerSecond = batchSize / Math.max(elapsedMs / 1000.0, 0.001);
            log.info("[Perf] encryptBatch: {} fields/sec ({} fields in {}ms)",
                    String.format("%.1f", fieldsPerSecond), batchSize, elapsedMs);

            assertTrue(fieldsPerSecond >= BATCH_MIN_FIELDS_PER_SECOND,
                    String.format("Batch encryption throughput %.1f fields/sec is below minimum %d fields/sec (Req 10.4)",
                            fieldsPerSecond, BATCH_MIN_FIELDS_PER_SECOND));
        }

        /**
         * Validates: 
         *
         * <p>Pre-encrypt 200+ fields, time the decryptBatch() call, and assert
         * throughput ≥ 100 fields/second.
         */
        @Test
        @DisplayName("decryptBatch achieves at least 100 fields per second")
        void decryptBatch_throughput_meetsMinimum() {
            int batchSize = 200;
            List<String> plaintexts = new ArrayList<>(batchSize);
            for (int i = 0; i < batchSize; i++) {
                plaintexts.add("user-" + i + "@example.com");
            }

            // Pre-encrypt
            Result<List<Ciphertext>, EncryptionError> encResult =
                    encryptionService.encryptBatch(plaintexts, BoundedContext.PROFILE);
            assertTrue(encResult.isSuccess(), "Pre-encryption must succeed");
            List<Ciphertext> ciphertexts = encResult.getValue().orElseThrow();

            // Warm up
            encryptionService.decryptBatch(ciphertexts.subList(0, 10), BoundedContext.PROFILE);

            // Measure
            long startNs = System.nanoTime();
            Result<List<String>, DecryptionError> result =
                    encryptionService.decryptBatch(ciphertexts, BoundedContext.PROFILE);
            long elapsedMs = (System.nanoTime() - startNs) / 1_000_000L;

            assertTrue(result.isSuccess(), "Batch decryption must succeed");
            assertEquals(batchSize, result.getValue().orElseThrow().size(),
                    "All fields must be decrypted");

            double fieldsPerSecond = batchSize / Math.max(elapsedMs / 1000.0, 0.001);
            log.info("[Perf] decryptBatch: {} fields/sec ({} fields in {}ms)",
                    String.format("%.1f", fieldsPerSecond), batchSize, elapsedMs);

            assertTrue(fieldsPerSecond >= BATCH_MIN_FIELDS_PER_SECOND,
                    String.format("Batch decryption throughput %.1f fields/sec is below minimum %d fields/sec (Req 10.4)",
                            fieldsPerSecond, BATCH_MIN_FIELDS_PER_SECOND));
        }
    }

    // =========================================================================
    // Cache hit rate > 90% 
    // =========================================================================

    @Nested
    @DisplayName("DEK cache hit rate (Req 10.1)")
    class CacheHitRateTests {

        /**
         * Validates: 
         *
         * <p>Uses a real {@link KeyManager} wired with a {@link DEKCache} and
         * {@link EncryptionMetrics}. After the first DEK rotation (which populates
         * the cache), N=100 encrypt operations all use the same active DEK — every
         * subsequent call after the first is a cache hit. Asserts hit rate ≥ 90%.
         */
        @Test
        @DisplayName("DEK cache hit rate is at least 90% for repeated operations on same context")
        void dekCacheHitRate_isAboveThreshold() {
            // Wire real KeyManager with DEKCache + EncryptionMetrics
            CountingKmsClient countingKms = new CountingKmsClient();
            DEKCache dekCache = new DEKCache(100, Duration.ofMinutes(60));
            IAuditLogger auditLogger = new NoOpAuditLogger();
            IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
            SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
            EncryptionMetrics metrics = new EncryptionMetrics(meterRegistry);

            KeyManager keyManager = new KeyManager(
                    countingKms, auditLogger, dekCache, Environment.DEV, ivCounter);
            keyManager.setEncryptionMetrics(metrics);

            BlindIndexService bis = new BlindIndexService(keyManager, "cache-hit-test-salt");
            EncryptionService svc = new EncryptionService(keyManager, bis, auditLogger, ivCounter);

            // Bootstrap: generate a KEK and rotate a DEK so the KeyManager has an active DEK
            Result<UUID, KeyError> kekResult = keyManager.rotateKEK(BoundedContext.PROFILE);
            assertTrue(kekResult.isSuccess(), "KEK rotation must succeed");

            Result<UUID, KeyError> dekResult = keyManager.rotateDEK(BoundedContext.PROFILE);
            assertTrue(dekResult.isSuccess(), "DEK rotation must succeed");

            // Warm up: first encrypt populates the DEK cache (1 cache miss expected)
            Result<Ciphertext, EncryptionError> warmup =
                    svc.encrypt("warmup@example.com", BoundedContext.PROFILE);
            assertTrue(warmup.isSuccess(), "Warm-up encryption must succeed");

            // Reset metrics after warm-up so we measure steady-state hit rate
            SimpleMeterRegistry freshRegistry = new SimpleMeterRegistry();
            EncryptionMetrics freshMetrics = new EncryptionMetrics(freshRegistry);
            keyManager.setEncryptionMetrics(freshMetrics);

            // Measure: N=100 encrypt operations using the same context (same active DEK)
            int n = 100;
            for (int i = 0; i < n; i++) {
                Result<Ciphertext, EncryptionError> r =
                        svc.encrypt("user-" + i + "@example.com", BoundedContext.PROFILE);
                assertTrue(r.isSuccess(), "Encryption must succeed during cache hit rate measurement");
            }

            double hitRate = freshMetrics.getCacheHitRate();
            log.info("[Perf] DEK cache hit rate: {}% over {} operations (KMS decrypt calls: {})",
                    String.format("%.1f", hitRate * 100), n, countingKms.decryptCallCount());

            assertTrue(hitRate >= CACHE_HIT_RATE_THRESHOLD,
                    String.format("DEK cache hit rate %.1f%% is below threshold of %.0f%% (Req 10.1)",
                            hitRate * 100, CACHE_HIT_RATE_THRESHOLD * 100));
        }
    }

    // =========================================================================
    // Test infrastructure
    // =========================================================================

    /**
     * Stub IKeyManager that always returns the same pre-generated DEK.
     * Simulates a fully warm DEK cache — no KMS calls, pure crypto latency.
     */
    static final class StubKeyManager implements IKeyManager {
        private final UUID keyId;
        private final DEK  dek;

        StubKeyManager(UUID keyId) {
            this.keyId = keyId;
            byte[] keyMaterial = new byte[32];
            new SecureRandom().nextBytes(keyMaterial);
            this.dek = DEK.of(keyMaterial);
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getActiveDEK(BoundedContext context) {
            return Result.success(buildMetadata(context));
        }

        @Override
        public Result<DEKWithMetadata, KeyError> getDEK(UUID id) {
            return Result.success(buildMetadata(BoundedContext.PROFILE));
        }

        private DEKWithMetadata buildMetadata(BoundedContext context) {
            return DEKWithMetadata.builder()
                    .dek(dek).keyId(keyId).kekId(UUID.randomUUID())
                    .context(context).environment(Environment.DEV)
                    .algorithm(EncryptionAlgorithm.AES_256_GCM)
                    .createdAt(Instant.now()).status(KeyStatus.ACTIVE)
                    .build();
        }

        @Override public Result<UUID, KeyError> rotateDEK(BoundedContext c) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }
        @Override public Result<UUID, KeyError> rotateKEK(BoundedContext c) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }
        @Override public Result<Void, KeyError> invalidateCache(UUID id) {
            return Result.success(null);
        }
        @Override public Result<DeletionCertificate, KeyError> deleteUserDEK(String userId, BoundedContext c) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }
        @Override public Result<byte[], KeyError> getBlindIndexKey() {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            return Result.success(key);
        }
    }

    /**
     * IKMSClient that performs real AES-GCM wrap/unwrap and counts decryptDEK calls.
     * Each decryptDEK call represents a DEK cache miss (KMS round-trip).
     */
    static final class CountingKmsClient implements IKMSClient {

        private static final SecureRandom RANDOM = new SecureRandom();
        private final Map<UUID, byte[]> kekStore = new ConcurrentHashMap<>();
        private final AtomicInteger decryptCalls = new AtomicInteger(0);

        int decryptCallCount() { return decryptCalls.get(); }

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
            decryptCalls.incrementAndGet(); // each call = cache miss
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

    /** No-op audit logger for tests. */
    static final class NoOpAuditLogger implements IAuditLogger {
        @SuppressWarnings({"unchecked", "rawtypes"})
        private static <E> Result<Void, E> ok() {
            return (Result<Void, E>) (Result) Result.success(Unit.unit());
        }

        @Override public Result<Void, AuditError> logEncryption(EncryptionEvent e)       { return ok(); }
        @Override public Result<Void, AuditError> logDecryption(DecryptionEvent e)       { return ok(); }
        @Override public Result<Void, AuditError> logKeyRotation(KeyRotationEvent e)     { return ok(); }
        @Override public Result<Void, AuditError> logSecurityEvent(SecurityEvent e)      { return ok(); }
        @Override public Result<Void, AuditError> logKeyAccess(KeyAccessEvent e)         { return ok(); }
        @Override public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent e) { return ok(); }
    }
}
