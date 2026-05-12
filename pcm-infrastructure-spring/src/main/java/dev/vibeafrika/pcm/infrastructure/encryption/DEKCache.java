package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.DEKWithMetadata;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * LRU cache for DEKs with TTL-based eviction and secure memory handling.
 * 
 * <p>Features:
 * <ul>
 *   <li>LRU eviction when cache exceeds max size (1000 entries)</li>
 *   <li>TTL-based eviction (1 hour default)</li>
 *   <li>Secure memory wiping on eviction</li>
 *   <li>Thread-safe operations using ReadWriteLock</li>
 * </ul>
 * 
 * <p>
 */
public class DEKCache {
    
    private static final int DEFAULT_MAX_SIZE = 1000;
    private static final Duration DEFAULT_TTL = Duration.ofHours(1);
    
    private final int maxSize;
    private final Duration ttl;
    private final Map<UUID, CacheEntry> cache;
    private final ReadWriteLock lock;
    
    /**
     * Creates a DEKCache with default settings (max size 1000, TTL 1 hour).
     */
    public DEKCache() {
        this(DEFAULT_MAX_SIZE, DEFAULT_TTL);
    }
    
    /**
     * Creates a DEKCache with custom settings.
     * 
     * @param maxSize maximum number of entries in the cache
     * @param ttl time-to-live for cached entries
     */
    public DEKCache(int maxSize, Duration ttl) {
        if (maxSize <= 0) {
            throw new IllegalArgumentException("Max size must be positive");
        }
        if (ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("TTL must be positive");
        }
        
        this.maxSize = maxSize;
        this.ttl = ttl;
        this.lock = new ReentrantReadWriteLock();
        
        // LinkedHashMap with access-order for LRU behavior
        this.cache = new LinkedHashMap<UUID, CacheEntry>(maxSize, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<UUID, CacheEntry> eldest) {
                if (size() > maxSize) {
                    // Securely wipe the evicted entry
                    eldest.getValue().wipe();
                    return true;
                }
                return false;
            }
        };
    }
    
    /**
     * Retrieves a DEK from the cache if present and not expired.
     * 
     * @param keyId the UUID of the DEK to retrieve
     * @return Optional containing the DEK with metadata if found and valid, empty otherwise
     */
    public Optional<DEKWithMetadata> get(UUID keyId) {
        lock.readLock().lock();
        try {
            CacheEntry entry = cache.get(keyId);
            if (entry == null) {
                return Optional.empty();
            }
            
            // Check if entry has expired
            if (entry.isExpired()) {
                // Need to upgrade to write lock to remove expired entry
                lock.readLock().unlock();
                lock.writeLock().lock();
                try {
                    // Double-check after acquiring write lock
                    entry = cache.get(keyId);
                    if (entry != null && entry.isExpired()) {
                        cache.remove(keyId);
                        entry.wipe();
                    }
                    return Optional.empty();
                } finally {
                    // Downgrade to read lock
                    lock.readLock().lock();
                    lock.writeLock().unlock();
                }
            }
            
            return Optional.of(entry.dekWithMetadata);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Stores a DEK in the cache with the current timestamp.
     * 
     * @param keyId the UUID of the DEK
     * @param dekWithMetadata the DEK with its metadata
     */
    public void put(UUID keyId, DEKWithMetadata dekWithMetadata) {
        lock.writeLock().lock();
        try {
            // Check if we're replacing an existing entry
            CacheEntry oldEntry = cache.get(keyId);
            if (oldEntry != null) {
                oldEntry.wipe();
            }
            
            cache.put(keyId, new CacheEntry(dekWithMetadata, Instant.now()));
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Invalidates a specific DEK from the cache, securely wiping its memory.
     * 
     * @param keyId the UUID of the DEK to invalidate
     */
    public void invalidate(UUID keyId) {
        lock.writeLock().lock();
        try {
            CacheEntry entry = cache.remove(keyId);
            if (entry != null) {
                entry.wipe();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Invalidates all DEKs from the cache, securely wiping their memory.
     */
    public void invalidateAll() {
        lock.writeLock().lock();
        try {
            cache.values().forEach(CacheEntry::wipe);
            cache.clear();
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Returns the current number of entries in the cache.
     */
    public int size() {
        lock.readLock().lock();
        try {
            return cache.size();
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Removes all expired entries from the cache.
     * This method should be called periodically to clean up expired entries.
     */
    public void evictExpired() {
        lock.writeLock().lock();
        try {
            cache.entrySet().removeIf(entry -> {
                if (entry.getValue().isExpired()) {
                    entry.getValue().wipe();
                    return true;
                }
                return false;
            });
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Cache entry containing a DEK with metadata and timestamp.
     */
    private class CacheEntry {
        private final DEKWithMetadata dekWithMetadata;
        private final Instant timestamp;
        
        CacheEntry(DEKWithMetadata dekWithMetadata, Instant timestamp) {
            this.dekWithMetadata = dekWithMetadata;
            this.timestamp = timestamp;
        }
        
        boolean isExpired() {
            return Instant.now().isAfter(timestamp.plus(ttl));
        }
        
        void wipe() {
            // Securely wipe the DEK key material from memory
            dekWithMetadata.getDek().wipe();
        }
    }
}
