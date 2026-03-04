package dev.vibeafrika.pcm.profile.application.config;

/**
 * Configuration interface for profile service settings.
 * No framework annotations - implemented by infrastructure layer.
 * 
 * Defines configuration contracts that infrastructure adapters must provide.
 */
public interface ProfileConfiguration {
    
    /**
     * Maximum number of attributes per profile.
     * Used to enforce limits on profile attribute storage.
     * 
     * @return Maximum attributes count
     */
    int getMaxAttributesPerProfile();
    
    /**
     * Whether to enable profile versioning.
     * When enabled, optimistic locking is used for concurrent updates.
     * 
     * @return true if versioning is enabled, false otherwise
     */
    boolean isVersioningEnabled();
    
    /**
     * Retention period for deleted profiles (in days).
     * After this period, deleted profiles may be permanently removed.
     * Used for GDPR compliance and data retention policies.
     * 
     * @return Retention period in days
     */
    int getDeletedProfileRetentionDays();
}
