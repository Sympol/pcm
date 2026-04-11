package dev.vibeafrika.pcm.domain.encryption.config;

/**
 * Cache eviction policy for the DEK cache.
 *
 * <p>{@link #LRU} (Least Recently Used) evicts the least recently accessed entry
 * when the cache reaches its maximum size.
 */
public enum EvictionPolicy {
    LRU
}
