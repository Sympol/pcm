package dev.vibeafrika.pcm.preference.application.dto;

import java.util.UUID;

/**
 * Request DTO for getting a preference.
 */
public record GetPreferenceRequest(
    UUID preferenceId,
    String tenantId
) {
    public GetPreferenceRequest {
        if (preferenceId == null) {
            throw new IllegalArgumentException("Preference ID is required");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
    }
}
