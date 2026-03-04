package dev.vibeafrika.pcm.preference.application.config;

/**
 * Configuration interface for preference service settings.
 * No framework annotations - implemented by infrastructure layer.
 * 
 * This interface defines the configuration contract that the application layer
 * needs. The infrastructure layer provides the actual implementation using
 * framework-specific configuration mechanisms (e.g., Spring @ConfigurationProperties,
 * Quarkus @ConfigProperty).
 */
public interface PreferenceConfiguration {
    
    /**
     * Maximum number of settings per preference.
     * Used to enforce business rules on preference size.
     * 
     * @return the maximum number of settings allowed
     */
    int getMaxSettingsPerPreference();
    
    /**
     * Whether to enable preference caching.
     * When enabled, frequently accessed preferences are cached in memory.
     * 
     * @return true if caching is enabled, false otherwise
     */
    boolean isCachingEnabled();
    
    /**
     * Cache time-to-live in seconds.
     * Determines how long preferences remain in cache before expiring.
     * Only applicable when caching is enabled.
     * 
     * @return the cache TTL in seconds
     */
    int getCacheTtlSeconds();
    
    /**
     * Whether to enable preference versioning.
     * When enabled, changes to preferences are tracked with version numbers.
     * 
     * @return true if versioning is enabled, false otherwise
     */
    boolean isVersioningEnabled();
    
    /**
     * Retention period for deleted preferences (in days).
     * Soft-deleted preferences are permanently removed after this period.
     * 
     * @return the retention period in days
     */
    int getDeletedPreferenceRetentionDays();
}
