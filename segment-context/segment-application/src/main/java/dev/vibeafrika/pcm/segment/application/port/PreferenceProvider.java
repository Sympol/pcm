package dev.vibeafrika.pcm.segment.application.port;

import java.util.Map;
import java.util.UUID;

/**
 * Port for retrieving preference data from the preference bounded context.
 */
public interface PreferenceProvider {
    
    /**
     * Get preference settings for a specific profile and tenant.
     * @param profileId the profile identifier
     * @param tenantId the tenant identifier
     * @return a map of preference settings
     */
    Map<String, Object> getPreferences(UUID profileId, String tenantId);
}
