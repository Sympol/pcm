package dev.vibeafrika.pcm.profile.application.dto;

import java.util.UUID;

/**
 * Request DTO for erasing a profile (GDPR compliance).
 * 
 * Uses Java record for immutability and conciseness.
 */
public record EraseProfileRequest(
    UUID profileId,
    String tenantId
) {
    /**
     * Compact constructor with validation.
     */
    public EraseProfileRequest {
        if (profileId == null) {
            throw new IllegalArgumentException("Profile ID is required");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
    }
}
