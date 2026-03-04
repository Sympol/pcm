package dev.vibeafrika.pcm.segment.application.config;

/**
 * Configuration interface for segment service settings.
 * No framework annotations - implemented by infrastructure layer.
 */
public interface SegmentConfiguration {
    
    /**
     * Maximum number of segments per tenant.
     */
    int getMaxSegmentsPerTenant();
    
    /**
     * Maximum number of criteria per segment.
     */
    int getMaxCriteriaPerSegment();
    
    /**
     * Whether segment caching is enabled.
     */
    boolean isSegmentCachingEnabled();
    
    /**
     * Cache TTL in seconds.
     */
    int getCacheTtlSeconds();
}
