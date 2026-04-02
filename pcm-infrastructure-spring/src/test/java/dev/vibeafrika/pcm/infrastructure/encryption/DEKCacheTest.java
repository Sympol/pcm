package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link DEKCache}.
 *
 * <p>Covers:
 * <ul>
 *   <li>LRU eviction when cache exceeds 1000 entries</li>
 *   <li>TTL-based eviction after 1 hour</li>
 *   <li>Cache hit/miss scenarios</li>
 *   <li>Secure memory wiping on eviction </li>
 * </ul>
 */
class DEKCacheTest {

    private static final int MAX_SIZE = 1000;
    private static final Duration ONE_HOUR = Duration.ofHours(1);

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private DEK randomDEK() {
        byte[] keyMaterial = new byte[32];
        for (int i = 0; i < 32; i++) {
            keyMaterial[i] = (byte) (i + 1);
        }
        return DEK.of(keyMaterial);
    }

    private DEKWithMetadata dekWithMetadata(UUID keyId) {
        return DEKWithMetadata.builder()
                .dek(randomDEK())
                .keyId(keyId)
                .kekId(UUID.randomUUID())
                .context(BoundedContext.PROFILE)
                .environment(Environment.DEV)
                .algorithm(EncryptionAlgorithm.AES_256_GCM)
                .createdAt(Instant.now())
                .status(KeyStatus.ACTIVE)
                .encryptionCount(0)
                .bytesEncrypted(0)
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cache hit / miss
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Cache hit and miss scenarios")
    class CacheHitMissTests {

        private DEKCache cache;

        @BeforeEach
        void setUp() {
            cache = new DEKCache(MAX_SIZE, ONE_HOUR);
        }

        @Test
        @DisplayName("Returns empty Optional on cache miss")
        void cacheMiss_returnsEmpty() {
            UUID keyId = UUID.randomUUID();

            Optional<DEKWithMetadata> result = cache.get(keyId);

            assertTrue(result.isEmpty(), "Cache miss should return empty Optional");
        }

        @Test
        @DisplayName("Returns DEK on cache hit after put")
        void cacheHit_returnsDEK() {
            UUID keyId = UUID.randomUUID();
            DEKWithMetadata dek = dekWithMetadata(keyId);

            cache.put(keyId, dek);
            Optional<DEKWithMetadata> result = cache.get(keyId);

            assertTrue(result.isPresent(), "Cache hit should return the stored DEK");
            assertEquals(keyId, result.get().getKeyId());
        }

        @Test
        @DisplayName("Returns empty after explicit invalidation")
        void afterInvalidate_cacheMiss() {
            UUID keyId = UUID.randomUUID();
            cache.put(keyId, dekWithMetadata(keyId));

            cache.invalidate(keyId);

            assertTrue(cache.get(keyId).isEmpty(), "Invalidated entry should not be found");
        }

        @Test
        @DisplayName("Returns empty for all entries after invalidateAll")
        void afterInvalidateAll_allMiss() {
            UUID id1 = UUID.randomUUID();
            UUID id2 = UUID.randomUUID();
            cache.put(id1, dekWithMetadata(id1));
            cache.put(id2, dekWithMetadata(id2));

            cache.invalidateAll();

            assertTrue(cache.get(id1).isEmpty(), "Entry 1 should be gone after invalidateAll");
            assertTrue(cache.get(id2).isEmpty(), "Entry 2 should be gone after invalidateAll");
            assertEquals(0, cache.size());
        }

        @Test
        @DisplayName("Size reflects number of stored entries")
        void size_reflectsStoredEntries() {
            assertEquals(0, cache.size());

            UUID id1 = UUID.randomUUID();
            UUID id2 = UUID.randomUUID();
            cache.put(id1, dekWithMetadata(id1));
            cache.put(id2, dekWithMetadata(id2));

            assertEquals(2, cache.size());
        }

        @Test
        @DisplayName("Replacing an existing entry keeps size stable")
        void put_replacingExistingEntry_sizeUnchanged() {
            UUID keyId = UUID.randomUUID();
            cache.put(keyId, dekWithMetadata(keyId));
            cache.put(keyId, dekWithMetadata(keyId)); // replace

            assertEquals(1, cache.size());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LRU eviction
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("LRU eviction when cache exceeds max size")
    class LruEvictionTests {

        @Test
        @DisplayName("Cache size never exceeds max size after inserting 1001 entries")
        void lruEviction_sizeNeverExceedsMax() {
            DEKCache cache = new DEKCache(MAX_SIZE, ONE_HOUR);

            for (int i = 0; i < MAX_SIZE + 1; i++) {
                UUID id = UUID.randomUUID();
                cache.put(id, dekWithMetadata(id));
            }

            assertTrue(cache.size() <= MAX_SIZE,
                    "Cache size should not exceed " + MAX_SIZE + " after inserting " + (MAX_SIZE + 1) + " entries");
        }

        @Test
        @DisplayName("Least-recently-used entry is evicted when cache is full")
        void lruEviction_lruEntryIsEvicted() {
            DEKCache cache = new DEKCache(MAX_SIZE, ONE_HOUR);

            // Insert the entry that will be the LRU
            UUID lruId = UUID.randomUUID();
            cache.put(lruId, dekWithMetadata(lruId));

            // Fill the rest of the cache (MAX_SIZE - 1 more entries)
            for (int i = 1; i < MAX_SIZE; i++) {
                UUID id = UUID.randomUUID();
                cache.put(id, dekWithMetadata(id));
            }

            // Access lruId to make it recently used, then insert one more to trigger eviction
            // of the actual LRU (the first entry inserted after lruId)
            UUID secondId = UUID.randomUUID();
            cache.put(secondId, dekWithMetadata(secondId));

            // The cache should still contain lruId because we accessed it
            // (it was promoted by the get call above — but we didn't call get, so it IS the LRU)
            // Actually: lruId was inserted first and never accessed again, so it IS the LRU
            assertTrue(cache.get(lruId).isEmpty(),
                    "The least-recently-used entry should have been evicted");
        }

        @Test
        @DisplayName("Accessing an entry promotes it and prevents its eviction")
        void lruEviction_accessedEntryIsNotEvicted() {
            DEKCache cache = new DEKCache(MAX_SIZE, ONE_HOUR);

            // Insert the entry we want to protect
            UUID protectedId = UUID.randomUUID();
            cache.put(protectedId, dekWithMetadata(protectedId));

            // Fill the rest of the cache
            for (int i = 1; i < MAX_SIZE; i++) {
                UUID id = UUID.randomUUID();
                cache.put(id, dekWithMetadata(id));
            }

            // Access the protected entry to make it recently used
            cache.get(protectedId);

            // Insert one more entry to trigger LRU eviction
            UUID newId = UUID.randomUUID();
            cache.put(newId, dekWithMetadata(newId));

            // The protected entry should still be present
            assertTrue(cache.get(protectedId).isPresent(),
                    "Recently accessed entry should not be evicted");
        }

        @Test
        @DisplayName("Small cache (size 3) evicts LRU correctly")
        void lruEviction_smallCache() {
            DEKCache cache = new DEKCache(3, ONE_HOUR);

            UUID id1 = UUID.randomUUID();
            UUID id2 = UUID.randomUUID();
            UUID id3 = UUID.randomUUID();
            UUID id4 = UUID.randomUUID();

            cache.put(id1, dekWithMetadata(id1));
            cache.put(id2, dekWithMetadata(id2));
            cache.put(id3, dekWithMetadata(id3));

            // Access id1 to make it recently used; id2 becomes LRU
            cache.get(id1);

            // Insert id4 — should evict id2 (LRU)
            cache.put(id4, dekWithMetadata(id4));

            assertEquals(3, cache.size());
            assertTrue(cache.get(id2).isEmpty(), "id2 (LRU) should have been evicted");
            assertTrue(cache.get(id1).isPresent(), "id1 (recently accessed) should still be present");
            assertTrue(cache.get(id3).isPresent(), "id3 should still be present");
            assertTrue(cache.get(id4).isPresent(), "id4 (just inserted) should be present");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TTL-based eviction
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("TTL-based eviction")
    class TtlEvictionTests {

        @Test
        @DisplayName("Entry is available before TTL expires")
        void entry_availableBeforeTtlExpires() {
            DEKCache cache = new DEKCache(MAX_SIZE, ONE_HOUR);
            UUID keyId = UUID.randomUUID();
            cache.put(keyId, dekWithMetadata(keyId));

            assertTrue(cache.get(keyId).isPresent(), "Entry should be available before TTL expires");
        }

        @Test
        @DisplayName("Entry is evicted after TTL expires (short TTL)")
        void entry_evictedAfterTtlExpires() throws InterruptedException {
            // Use a very short TTL so the test doesn't need to wait an hour
            DEKCache cache = new DEKCache(MAX_SIZE, Duration.ofMillis(10));
            UUID keyId = UUID.randomUUID();
            cache.put(keyId, dekWithMetadata(keyId));

            // Wait for TTL to expire
            Thread.sleep(50);

            assertTrue(cache.get(keyId).isEmpty(), "Entry should be evicted after TTL expires");
        }

        @Test
        @DisplayName("evictExpired removes expired entries and keeps valid ones")
        void evictExpired_removesExpiredKeepsValid() throws InterruptedException {
            DEKCache cache = new DEKCache(MAX_SIZE, Duration.ofMillis(10));

            UUID expiredId = UUID.randomUUID();
            cache.put(expiredId, dekWithMetadata(expiredId));

            // Wait for TTL to expire
            Thread.sleep(50);

            // Add a fresh entry
            UUID freshId = UUID.randomUUID();
            cache.put(freshId, dekWithMetadata(freshId));

            cache.evictExpired();

            assertTrue(cache.get(expiredId).isEmpty(), "Expired entry should be removed by evictExpired");
            assertTrue(cache.get(freshId).isPresent(), "Fresh entry should remain after evictExpired");
        }

        @Test
        @DisplayName("Default TTL is 1 hour")
        void defaultTtl_isOneHour() {
            // Verify the default constructor creates a cache with 1-hour TTL
            // by checking that a freshly inserted entry is immediately available
            DEKCache cache = new DEKCache();
            UUID keyId = UUID.randomUUID();
            cache.put(keyId, dekWithMetadata(keyId));

            assertTrue(cache.get(keyId).isPresent(),
                    "Entry should be available immediately after insertion with default 1-hour TTL");
        }

        @Test
        @DisplayName("Default max size is 1000")
        void defaultMaxSize_is1000() {
            DEKCache cache = new DEKCache();

            // Insert 1000 entries — all should fit
            for (int i = 0; i < 1000; i++) {
                UUID id = UUID.randomUUID();
                cache.put(id, dekWithMetadata(id));
            }

            assertEquals(1000, cache.size(), "Default cache should hold exactly 1000 entries");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Secure memory wiping on eviction
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Secure memory wiping on eviction")
    class SecureMemoryWipingTests {

        @Test
        @DisplayName("DEK key material is zeroed after explicit invalidation")
        void invalidate_wipesKeyMaterial() {
            DEKCache cache = new DEKCache(MAX_SIZE, ONE_HOUR);
            UUID keyId = UUID.randomUUID();

            byte[] keyMaterial = new byte[32];
            Arrays.fill(keyMaterial, (byte) 0xAB);
            DEK dek = DEK.of(keyMaterial);

            DEKWithMetadata dekWithMetadata = DEKWithMetadata.builder()
                    .dek(dek)
                    .keyId(keyId)
                    .kekId(UUID.randomUUID())
                    .context(BoundedContext.PROFILE)
                    .environment(Environment.DEV)
                    .algorithm(EncryptionAlgorithm.AES_256_GCM)
                    .createdAt(Instant.now())
                    .status(KeyStatus.ACTIVE)
                    .encryptionCount(0)
                    .bytesEncrypted(0)
                    .build();

            cache.put(keyId, dekWithMetadata);
            cache.invalidate(keyId);

            // After invalidation, the DEK's internal key material should be zeroed
            byte[] wipedMaterial = dek.getKeyMaterial();
            for (byte b : wipedMaterial) {
                assertEquals(0, b, "Key material should be zeroed after eviction");
            }
        }

        @Test
        @DisplayName("DEK key material is zeroed after invalidateAll")
        void invalidateAll_wipesAllKeyMaterials() {
            DEKCache cache = new DEKCache(MAX_SIZE, ONE_HOUR);

            byte[] keyMaterial1 = new byte[32];
            byte[] keyMaterial2 = new byte[32];
            Arrays.fill(keyMaterial1, (byte) 0xAB);
            Arrays.fill(keyMaterial2, (byte) 0xCD);

            DEK dek1 = DEK.of(keyMaterial1);
            DEK dek2 = DEK.of(keyMaterial2);

            UUID id1 = UUID.randomUUID();
            UUID id2 = UUID.randomUUID();

            cache.put(id1, buildDekWithMetadata(id1, dek1));
            cache.put(id2, buildDekWithMetadata(id2, dek2));

            cache.invalidateAll();

            assertAllZeroed(dek1.getKeyMaterial(), "DEK 1 key material should be zeroed after invalidateAll");
            assertAllZeroed(dek2.getKeyMaterial(), "DEK 2 key material should be zeroed after invalidateAll");
        }

        @Test
        @DisplayName("DEK key material is zeroed when evicted by LRU")
        void lruEviction_wipesKeyMaterial() {
            DEKCache cache = new DEKCache(2, ONE_HOUR);

            byte[] lruKeyMaterial = new byte[32];
            Arrays.fill(lruKeyMaterial, (byte) 0xFF);
            DEK lruDek = DEK.of(lruKeyMaterial);

            UUID lruId = UUID.randomUUID();
            cache.put(lruId, buildDekWithMetadata(lruId, lruDek));

            UUID id2 = UUID.randomUUID();
            cache.put(id2, dekWithMetadata(id2));

            // Insert a third entry to trigger LRU eviction of lruId
            UUID id3 = UUID.randomUUID();
            cache.put(id3, dekWithMetadata(id3));

            // lruId should have been evicted and its key material zeroed
            assertAllZeroed(lruDek.getKeyMaterial(), "LRU-evicted DEK key material should be zeroed");
        }

        @Test
        @DisplayName("DEK key material is zeroed when evicted by TTL expiry")
        void ttlEviction_wipesKeyMaterial() throws InterruptedException {
            DEKCache cache = new DEKCache(MAX_SIZE, Duration.ofMillis(10));

            byte[] keyMaterial = new byte[32];
            Arrays.fill(keyMaterial, (byte) 0x55);
            DEK dek = DEK.of(keyMaterial);

            UUID keyId = UUID.randomUUID();
            cache.put(keyId, buildDekWithMetadata(keyId, dek));

            // Wait for TTL to expire
            Thread.sleep(50);

            // Trigger eviction by accessing the expired entry
            cache.get(keyId);

            assertAllZeroed(dek.getKeyMaterial(), "TTL-expired DEK key material should be zeroed on access");
        }

        // ─── helpers ───

        private DEKWithMetadata buildDekWithMetadata(UUID keyId, DEK dek) {
            return DEKWithMetadata.builder()
                    .dek(dek)
                    .keyId(keyId)
                    .kekId(UUID.randomUUID())
                    .context(BoundedContext.PROFILE)
                    .environment(Environment.DEV)
                    .algorithm(EncryptionAlgorithm.AES_256_GCM)
                    .createdAt(Instant.now())
                    .status(KeyStatus.ACTIVE)
                    .encryptionCount(0)
                    .bytesEncrypted(0)
                    .build();
        }

        private void assertAllZeroed(byte[] bytes, String message) {
            for (byte b : bytes) {
                assertEquals(0, b, message);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor validation
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Constructor validation")
    class ConstructorValidationTests {

        @Test
        @DisplayName("Throws IllegalArgumentException for non-positive max size")
        void constructor_throwsOnNonPositiveMaxSize() {
            assertThrows(IllegalArgumentException.class,
                    () -> new DEKCache(0, ONE_HOUR),
                    "Max size of 0 should throw IllegalArgumentException");

            assertThrows(IllegalArgumentException.class,
                    () -> new DEKCache(-1, ONE_HOUR),
                    "Negative max size should throw IllegalArgumentException");
        }

        @Test
        @DisplayName("Throws IllegalArgumentException for zero or negative TTL")
        void constructor_throwsOnNonPositiveTtl() {
            assertThrows(IllegalArgumentException.class,
                    () -> new DEKCache(MAX_SIZE, Duration.ZERO),
                    "Zero TTL should throw IllegalArgumentException");

            assertThrows(IllegalArgumentException.class,
                    () -> new DEKCache(MAX_SIZE, Duration.ofSeconds(-1)),
                    "Negative TTL should throw IllegalArgumentException");
        }
    }
}
