package dev.vibeafrika.pcm.profile.application.port;

import dev.vibeafrika.pcm.profile.application.dto.ProfileDataExportResponse;
import java.util.List;
import java.util.UUID;

/**
 * Port for retrieving consent data from the Consent bounded context.
 */
public interface ConsentProvider {
    /**
     * Get all consents and their history for a given profile.
     *
     * @param profileId the profile unique identifier
     * @return a list of consent export entries
     */
    List<ProfileDataExportResponse.ConsentExportEntry> getConsentsForProfile(UUID profileId);
}
