package dev.vibeafrika.pcm.consent.application.config;

/**
 * Configuration interface for consent service settings.
 * No framework annotations - implemented by infrastructure layer.
 */
public interface ConsentConfiguration {
    
    /**
     * Retention period for consent records (in years).
     */
    int getConsentRetentionYears();
    
    /**
     * Whether to enable IAB TCF integration.
     */
    boolean isEnableTCFIntegration();
}
