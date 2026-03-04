package dev.vibeafrika.pcm.preference.application.dto;

import dev.vibeafrika.pcm.preference.domain.model.Preference;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Response DTO for preference operations.
 */
public record PreferenceResponse(
    UUID id,
    String tenantId,
    UUID profileId,
    Map<String, String> settings,
    Instant lastUpdated
) {
    /**
     * Factory method to create a PreferenceResponse from a domain Preference entity.
     */
    public static PreferenceResponse from(Preference preference) {
        return new PreferenceResponse(
            preference.getId().getValue(),
            preference.getTenantId().getValue(),
            preference.getProfileId().getValue(),
            preference.getSettings(),
            preference.getLastUpdated()
        );
    }
}
