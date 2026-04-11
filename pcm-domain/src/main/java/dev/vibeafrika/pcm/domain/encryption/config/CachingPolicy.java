package dev.vibeafrika.pcm.domain.encryption.config;

import java.time.Duration;
import java.util.Objects;

/**
 * Policy governing the in-memory DEK cache.
 *
 * <p>Defaults:
 * <ul>
 *   <li>TTL: 1 hour</li>
 *   <li>Max size: 1000 entries</li>
 *   <li>Eviction policy: LRU</li>
 *   <li>Secure memory: {@code false} (platform-dependent)</li>
 * </ul>
 */
public final class CachingPolicy {

    /** Default DEK cache TTL. */
    public static final Duration DEFAULT_DEK_CACHE_TTL = Duration.ofHours(1);

    /** Default maximum number of DEKs held in the cache. */
    public static final int DEFAULT_DEK_CACHE_MAX_SIZE = 1000;

    private final Duration dekCacheTTL;
    private final int dekCacheMaxSize;
    private final EvictionPolicy evictionPolicy;
    private final boolean secureMemory;

    private CachingPolicy(Builder builder) {
        this.dekCacheTTL = Objects.requireNonNull(builder.dekCacheTTL, "dekCacheTTL cannot be null");
        if (builder.dekCacheMaxSize < 1) {
            throw new IllegalArgumentException("dekCacheMaxSize must be >= 1");
        }
        this.dekCacheMaxSize = builder.dekCacheMaxSize;
        this.evictionPolicy = Objects.requireNonNull(builder.evictionPolicy, "evictionPolicy cannot be null");
        this.secureMemory = builder.secureMemory;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Creates a policy with all default values. */
    public static CachingPolicy defaults() {
        return new Builder().build();
    }

    public Duration getDekCacheTTL() {
        return dekCacheTTL;
    }

    public int getDekCacheMaxSize() {
        return dekCacheMaxSize;
    }

    public EvictionPolicy getEvictionPolicy() {
        return evictionPolicy;
    }

    /**
     * Whether to use secure (locked/pinned) memory for cached DEK material.
     * When {@code true}, the runtime will attempt to prevent key bytes from
     * being swapped to disk.
     */
    public boolean isSecureMemory() {
        return secureMemory;
    }

    public static final class Builder {
        private Duration dekCacheTTL = DEFAULT_DEK_CACHE_TTL;
        private int dekCacheMaxSize = DEFAULT_DEK_CACHE_MAX_SIZE;
        private EvictionPolicy evictionPolicy = EvictionPolicy.LRU;
        private boolean secureMemory = false;

        private Builder() {}

        public Builder dekCacheTTL(Duration dekCacheTTL) {
            this.dekCacheTTL = dekCacheTTL;
            return this;
        }

        public Builder dekCacheMaxSize(int dekCacheMaxSize) {
            this.dekCacheMaxSize = dekCacheMaxSize;
            return this;
        }

        public Builder evictionPolicy(EvictionPolicy evictionPolicy) {
            this.evictionPolicy = evictionPolicy;
            return this;
        }

        public Builder secureMemory(boolean secureMemory) {
            this.secureMemory = secureMemory;
            return this;
        }

        public CachingPolicy build() {
            return new CachingPolicy(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CachingPolicy that = (CachingPolicy) o;
        return dekCacheMaxSize == that.dekCacheMaxSize &&
                secureMemory == that.secureMemory &&
                Objects.equals(dekCacheTTL, that.dekCacheTTL) &&
                evictionPolicy == that.evictionPolicy;
    }

    @Override
    public int hashCode() {
        return Objects.hash(dekCacheTTL, dekCacheMaxSize, evictionPolicy, secureMemory);
    }

    @Override
    public String toString() {
        return "CachingPolicy{" +
                "dekCacheTTL=" + dekCacheTTL +
                ", dekCacheMaxSize=" + dekCacheMaxSize +
                ", evictionPolicy=" + evictionPolicy +
                ", secureMemory=" + secureMemory +
                '}';
    }
}
