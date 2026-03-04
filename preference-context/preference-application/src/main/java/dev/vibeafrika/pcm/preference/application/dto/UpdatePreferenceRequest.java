package dev.vibeafrika.pcm.preference.application.dto;

import java.util.Map;
import java.util.UUID;

/**
 * Request DTO for updating a preference.
 */
public record UpdatePreferenceRequest(
    UUID preferenceId,
    String tenantId,
    Map<String, String> settings
) {
    public UpdatePreferenceRequest {
        if (preferenceId == null) {
            throw new IllegalArgumentException("Preference ID is required");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
        if (settings == null || settings.isEmpty()) {
            throw new IllegalArgumentException("Settings cannot be null or empty");
        }
    }
}
