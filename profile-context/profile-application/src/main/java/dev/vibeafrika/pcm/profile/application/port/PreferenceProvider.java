package dev.vibeafrika.pcm.profile.application.port;

import dev.vibeafrika.pcm.profile.application.dto.ProfileDataExportResponse;
import java.util.List;
import java.util.UUID;

/**
 * Port for retrieving preference data from the Preference bounded context.
 */
public interface PreferenceProvider {
    /**
     * Get all preferences for a given profile and tenant.
     *
     * @param profileId the profile unique identifier
     * @param tenantId the tenant unique identifier
     * @return a list of preference export entries
     */
    List<ProfileDataExportResponse.PreferenceExportEntry> getPreferencesForProfile(UUID profileId, String tenantId);
}
