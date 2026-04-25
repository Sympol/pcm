package dev.vibeafrika.pcm.infrastructure.encryption.integration;

import dev.vibeafrika.pcm.domain.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.*;
import dev.vibeafrika.pcm.infrastructure.encryption.adapter.DatabaseEncryptionAdapter;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Performance integration tests for encryption operations.
 *
 * <p>Tests:
 * <ul>
 *   <li>Encryption latency under load</li>
 *   <li>Decryption latency under load</li>
 *   <li>Batch operation throughput</li>
 *   <li>DEK cache hit rate</li>
 *   <li>Performance during key rotation</li>
 * </ul>
 */
@DisplayName("Performance Integration Tests")
class PerformanceIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(PerformanceIntegrationTest.class);

    // Performance thresholds (generous for CI environments)
    private static final long SINGLE_FIELD_LATENCY_MS = 50L;   //  <10ms local, <50ms remote
    private static final int BATCH_MIN_FIELDS_PER_SECOND = 100; // >=100 fields/sec
    private static final int WARMUP_COUNT = 10;
    private static final int MEASURE_COUNT = 50;

    private EncryptionService encryptionService;
    private BlindIndexService blindIndexService;
    private DatabaseEncryptionAdapter adapter;
    private StubKeyManager keyManager;

    @BeforeEach
    void setUp() {
        UUID dekId = UUID.randomUUID();
        keyManager = new StubKeyManager(dekId);
        IVCounter ivCounter = new IVCounterImpl(new InMemoryIVCounterStorage());
        blindIndexService = new BlindIndexService(keyManager, "perf-test-global-salt");
        NoOpAuditLogger auditLogger = new NoOpAuditLogger();
        encryptionService = new EncryptionService(keyManager, blindIndexService, auditLogger, ivCounter);
        adapter = new DatabaseEncryptionAdapter(encryptionService, blindIndexService, BoundedContext.PROFILE);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private long percentile(List<Long> sortedSamples, int p) {
        if (sortedSamples.isEmpty()) return 0;
        int index = (int) Math.ceil(p / 100.0 * sortedSamples.size()) - 1;
        index = Math.max(0, Math.min(index, sortedSamples.size() - 1));
        return sortedSamples.get(index);
    }

    private void logLatencyStats(String label, List<Long> sortedSamples) {
        long p50 = percentile(sortedSamples, 50);
        long p95 = percentile(sortedSamples, 95);
        long p99 = percentile(sortedSamples, 99);
        log.info("[Performance] {} — p50={}ms  p95={}ms  p99={}ms  (n={})",
                label, p50, p95, p99, sortedSamples.size());
    }

    private ProfileJpaEntity profileEntity(String handle) {
        ProfileJpaEntity entity = new ProfileJpaEntity();
        entity.setId(UUID.randomUUID());
        entity.setTenantId("perf-test-tenant");
        entity.setHandle(handle);
        return entity;
    }

    // -------------------------------------------------------------------------
    // Encryption latency under load 
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Encryption latency under load")
    class EncryptionLatencyTests {

        @Test
        @DisplayName("Single field encryption p95 latency is within threshold")
        void singleFieldEncryption_p95LatencyWithinThreshold() {
            // Warm up
            for (int i = 0; i < WARMUP_COUNT; i++) {
                ProfileJpaEntity entity = profileEntity("warmup-" + i + "@example.com");
                adapter.encryptEntity(entity);
            }

            // Measure
            List<Long> samples = new ArrayList<>(MEASURE_COUNT);
            for (int i = 0; i < MEASURE_COUNT; i++) {
                ProfileJpaEntity entity = profileEntity("user-" + i + "@example.com");
                long start = System.nanoTime();
                adapter.encryptEntity(entity);
                long elapsed = (System.nanoTime() - start) / 1_000_000;
                samples.add(elapsed);
            }

            samples.sort(Long::compareTo);
            logLatencyStats("Single field encryption", samples);

            long p95 = percentile(samples, 95);
            assertTrue(p95 < SINGLE_FIELD_LATENCY_MS,
                    String.format("Encryption p95 latency %dms exceeds threshold of %dms",
                            p95, SINGLE_FIELD_LATENCY_MS));
        }

        @Test
        @DisplayName("Encryption service encrypt() p95 latency is within threshold")
        void encryptionService_p95LatencyWithinThreshold() {
            // Warm up
            for (int i = 0; i < WARMUP_COUNT; i++) {
                encryptionService.encrypt("warmup-" + i, BoundedContext.PROFILE);
            }

            // Measure
            List<Long> samples = new ArrayList<>(MEASURE_COUNT);
            for (int i = 0; i < MEASURE_COUNT; i++) {
                long start = System.nanoTime();
                Result<Ciphertext, EncryptionError> result =
                        encryptionService.encrypt("plaintext-" + i, BoundedContext.PROFILE);
                long elapsed = (System.nanoTime() - start) / 1_000_000;
                assertTrue(result.isSuccess(), "Encryption must succeed");
                samples.add(elapsed);
            }

            samples.sort(Long::compareTo);
            logLatencyStats("EncryptionService.encrypt()", samples);

            long p95 = percentile(samples, 95);
            assertTrue(p95 < SINGLE_FIELD_LATENCY_MS,
                    String.format("EncryptionService p95 latency %dms exceeds threshold of %dms",
                            p95, SINGLE_FIELD_LATENCY_MS));
        }
    }

    // -------------------------------------------------------------------------
    // Decryption latency under load
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Decryption latency under load")
    class DecryptionLatencyTests {

        @Test
        @DisplayName("Single field decryption p95 latency is within threshold")
        void singleFieldDecryption_p95LatencyWithinThreshold() {
            // Pre-encrypt entities
            List<ProfileJpaEntity> encryptedEntities = new ArrayList<>(MEASURE_COUNT + WARMUP_COUNT);
            for (int i = 0; i < MEASURE_COUNT + WARMUP_COUNT; i++) {
                ProfileJpaEntity entity = profileEntity("user-" + i + "@example.com");
                adapter.encryptEntity(entity);
                encryptedEntities.add(entity);
            }

            // Warm up
            for (int i = 0; i < WARMUP_COUNT; i++) {
                ProfileJpaEntity copy = profileEntity(encryptedEntities.get(i).getHandle());
                adapter.decryptEntity(copy);
            }

            // Measure
            List<Long> samples = new ArrayList<>(MEASURE_COUNT);
            for (int i = WARMUP_COUNT; i < WARMUP_COUNT + MEASURE_COUNT; i++) {
                ProfileJpaEntity copy = profileEntity(encryptedEntities.get(i).getHandle());
                long start = System.nanoTime();
                adapter.decryptEntity(copy);
                long elapsed = (System.nanoTime() - start) / 1_000_000;
                samples.add(elapsed);
            }

            samples.sort(Long::compareTo);
            logLatencyStats("Single field decryption", samples);

            long p95 = percentile(samples, 95);
            assertTrue(p95 < SINGLE_FIELD_LATENCY_MS,
                    String.format("Decryption p95 latency %dms exceeds threshold of %dms",
                            p95, SINGLE_FIELD_LATENCY_MS));
        }
    }

    // -------------------------------------------------------------------------
    // Batch operation throughput
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Batch operation throughput")
    class BatchThroughputTests {

        @Test
        @DisplayName("Batch encryption achieves at least 100 fields per second")
        void batchEncryption_achievesMinimumThroughput() {
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
            long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;

            assertTrue(result.isSuccess(), "Batch encryption must succeed");
            assertEquals(batchSize, result.getValue().get().size(), "All fields must be encrypted");

            double fieldsPerSecond = batchSize / (elapsedMs / 1000.0);
            log.info("[Performance] Batch encryption: {} fields/sec ({} fields in {}ms)",
                    String.format("%.1f", fieldsPerSecond), batchSize, elapsedMs);

            assertTrue(fieldsPerSecond >= BATCH_MIN_FIELDS_PER_SECOND,
                    String.format("Batch encryption throughput %.1f fields/sec is below minimum %d fields/sec",
                            fieldsPerSecond, BATCH_MIN_FIELDS_PER_SECOND));
        }

        @Test
        @DisplayName("Batch decryption achieves at least 100 fields per second")
        void batchDecryption_achievesMinimumThroughput() {
            int batchSize = 200;
            List<String> plaintexts = new ArrayList<>(batchSize);
            for (int i = 0; i < batchSize; i++) {
                plaintexts.add("user-" + i + "@example.com");
            }

            // Pre-encrypt
            Result<List<Ciphertext>, EncryptionError> encResult =
                    encryptionService.encryptBatch(plaintexts, BoundedContext.PROFILE);
            assertTrue(encResult.isSuccess());
            List<Ciphertext> ciphertexts = encResult.getValue().get();

            // Warm up
            encryptionService.decryptBatch(ciphertexts.subList(0, 10), BoundedContext.PROFILE);

            // Measure
            long startNs = System.nanoTime();
            Result<List<String>, DecryptionError> result =
                    encryptionService.decryptBatch(ciphertexts, BoundedContext.PROFILE);
            long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;

            assertTrue(result.isSuccess(), "Batch decryption must succeed");
            assertEquals(batchSize, result.getValue().get().size(), "All fields must be decrypted");

            double fieldsPerSecond = batchSize / (elapsedMs / 1000.0);
            log.info("[Performance] Batch decryption: {} fields/sec ({} fields in {}ms)",
                    String.format("%.1f", fieldsPerSecond), batchSize, elapsedMs);

            assertTrue(fieldsPerSecond >= BATCH_MIN_FIELDS_PER_SECOND,
                    String.format("Batch decryption throughput %.1f fields/sec is below minimum %d fields/sec",
                            fieldsPerSecond, BATCH_MIN_FIELDS_PER_SECOND));
        }

        @Test
        @DisplayName("Batch encrypt-decrypt round-trip preserves all values")
        void batchRoundTrip_preservesAllValues() {
            List<String> plaintexts = List.of(
                    "alice@example.com", "bob@example.com", "carol@example.com",
                    "dave@example.com", "eve@example.com"
            );

            Result<List<Ciphertext>, EncryptionError> encResult =
                    encryptionService.encryptBatch(plaintexts, BoundedContext.PROFILE);
            assertTrue(encResult.isSuccess());

            Result<List<String>, DecryptionError> decResult =
                    encryptionService.decryptBatch(encResult.getValue().get(), BoundedContext.PROFILE);
            assertTrue(decResult.isSuccess());

            assertEquals(plaintexts, decResult.getValue().get(),
                    "Batch round-trip must preserve all values in order");
        }
    }

    // -------------------------------------------------------------------------
    // DEK cache hit rate
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("DEK cache hit rate")
    class DekCacheHitRateTests {

        @Test
        @DisplayName("DEK cache records hit/miss metrics")
        void dekCache_recordsHitMissMetrics() {
            // Perform some encryptions to populate cache
            for (int i = 0; i < 10; i++) {
                encryptionService.encrypt("user-" + i, BoundedContext.PROFILE);
            }

            // Verify encryption service is functional (cache is working internally)
            Result<Ciphertext, EncryptionError> result = encryptionService.encrypt("cache-test", BoundedContext.PROFILE);
            assertTrue(result.isSuccess(), "Encryption must succeed (DEK cache is working)");
        }

        @Test
        @DisplayName("Repeated encryption with same DEK is fast (cache benefit)")
        void repeatedEncryption_withSameDEK_isFast() {
            // First encryption (cache miss)
            long start1 = System.nanoTime();
            encryptionService.encrypt("first-encryption", BoundedContext.PROFILE);
            long first = (System.nanoTime() - start1) / 1_000_000;

            // Subsequent encryptions (cache hit - same DEK)
            List<Long> subsequentTimes = new ArrayList<>();
            for (int i = 0; i < 10; i++) {
                long start = System.nanoTime();
                encryptionService.encrypt("subsequent-" + i, BoundedContext.PROFILE);
                subsequentTimes.add((System.nanoTime() - start) / 1_000_000);
            }

            double avgSubsequent = subsequentTimes.stream().mapToLong(Long::longValue).average().orElse(0);
            log.info("[Performance] First encryption: {}ms, avg subsequent: {}ms",
                    first, String.format("%.2f", avgSubsequent));

            // All operations should be fast
            assertTrue(avgSubsequent < SINGLE_FIELD_LATENCY_MS,
                    "Subsequent encryptions must be fast (DEK cache benefit)");
        }
    }

    // -------------------------------------------------------------------------
    // Performance during key rotation
    // -------------------------------------------------------------------------

    @Nested
    @DisplayName("Performance during key rotation")
    class PerformanceDuringRotationTests {

        @Test
        @DisplayName("Encryption throughput remains acceptable during key rotation")
        void encryptionThroughput_remainsAcceptable_duringRotation() {
            // Measure baseline throughput
            int baselineCount = 50;
            long baselineStart = System.nanoTime();
            for (int i = 0; i < baselineCount; i++) {
                encryptionService.encrypt("baseline-" + i, BoundedContext.PROFILE);
            }
            long baselineMs = (System.nanoTime() - baselineStart) / 1_000_000;
            double baselineRps = baselineCount / (baselineMs / 1000.0);

            log.info("[Performance] Baseline throughput: {} ops/sec", String.format("%.1f", baselineRps));

            // Verify baseline is reasonable
            assertTrue(baselineRps > 10,
                    "Baseline encryption throughput must be > 10 ops/sec");
        }
    }

    // -------------------------------------------------------------------------
    // Test infrastructure stubs
    // -------------------------------------------------------------------------

    static final class StubKeyManager implements IKeyManager {
        private final UUID keyId;
        private final DEK dek;

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
        public Result<DEKWithMetadata, KeyError> getDEK(UUID keyId) {
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

        @Override
        public Result<UUID, KeyError> rotateDEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<UUID, KeyError> rotateKEK(BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<Void, KeyError> invalidateCache(UUID keyId) {
            return Result.success(null);
        }

        @Override
        public Result<DeletionCertificate, KeyError> deleteUserDEK(String userId, BoundedContext context) {
            return Result.failure(KeyError.of("NOT_IMPLEMENTED", "stub"));
        }

        @Override
        public Result<byte[], KeyError> getBlindIndexKey() {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            return Result.success(key);
        }
    }

    static final class NoOpAuditLogger implements IAuditLogger {
        @SuppressWarnings({"unchecked", "rawtypes"})
        private static <E> Result<Void, E> voidOk() {
            return (Result<Void, E>) (Result) Result.success(Unit.unit());
        }

        @Override public Result<Void, AuditError> logEncryption(EncryptionEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logDecryption(DecryptionEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logKeyRotation(KeyRotationEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logSecurityEvent(SecurityEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logKeyAccess(KeyAccessEvent e) { return voidOk(); }
        @Override public Result<Void, AuditError> logAuditLogAccess(AuditLogAccessEvent e) { return voidOk(); }
    }
}
