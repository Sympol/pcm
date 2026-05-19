package dev.vibeafrika.pcm.profile.application.dto;

import java.util.Map;
import java.util.UUID;

/**
 * Request DTO for updating a profile.
 * 
 * Uses Java record for immutability and conciseness.
 */
public record UpdateProfileRequest(
    UUID profileId,
    String tenantId,
    Map<String, Object> attributes
) {
    /**
     * Compact constructor with validation.
     */
    public UpdateProfileRequest {
        if (profileId == null) {
            throw new IllegalArgumentException("Profile ID is required");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
        attributes = attributes != null ? Map.copyOf(attributes) : Map.of();
    }
}
