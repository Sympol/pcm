package dev.vibeafrika.pcm.preference.application.dto;

import java.util.UUID;

/**
 * Request DTO for deleting a preference.
 */
public record DeletePreferenceRequest(
    UUID preferenceId,
    String tenantId
) {
    public DeletePreferenceRequest {
        if (preferenceId == null) {
            throw new IllegalArgumentException("Preference ID is required");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
    }
}
