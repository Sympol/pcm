package dev.vibeafrika.pcm.profile.application.dto;

import java.util.Map;

/**
 * Request DTO for creating a profile.
 * 
 * Uses Java record for immutability and conciseness.
 */
public record CreateProfileRequest(
    String tenantId,
    String handle,
    Map<String, Object> attributes
) {
    /**
     * Compact constructor with validation.
     */
    public CreateProfileRequest {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
        if (handle == null || handle.isBlank()) {
            throw new IllegalArgumentException("Handle is required");
        }
        // attributes can be null or empty
    }
}
