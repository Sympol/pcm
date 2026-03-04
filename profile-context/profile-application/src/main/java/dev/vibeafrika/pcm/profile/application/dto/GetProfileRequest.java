package dev.vibeafrika.pcm.profile.application.dto;

import java.util.UUID;

/**
 * Request DTO for retrieving a profile.
 * 
 * Uses Java record for immutability and conciseness.
 */
public record GetProfileRequest(
    UUID profileId,
    String tenantId
) {
    /**
     * Compact constructor with validation.
     */
    public GetProfileRequest {
        if (profileId == null) {
            throw new IllegalArgumentException("Profile ID is required");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
    }
}
