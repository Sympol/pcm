package dev.vibeafrika.pcm.preference.application.dto;

import java.util.Map;
import java.util.UUID;

/**
 * Request DTO for creating a preference.
 */
public record CreatePreferenceRequest(
    String tenantId,
    UUID profileId,
    Map<String, String> settings
) {
    public CreatePreferenceRequest {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
        if (profileId == null) {
            throw new IllegalArgumentException("Profile ID is required");
        }
        if (settings == null) {
            throw new IllegalArgumentException("Settings cannot be null");
        }
    }
}
