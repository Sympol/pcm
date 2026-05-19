package dev.vibeafrika.pcm.profile.application.dto;

import dev.vibeafrika.pcm.profile.domain.model.Profile;

import java.util.Map;
import java.util.UUID;

/**
 * Response DTO for profile operations.
 * 
 * Uses Java record for immutability and conciseness.
 */
public record ProfileResponse(
    UUID id,
    String tenantId,
    String handle,
    Map<String, Object> attributes,
    String createdAt,
    String updatedAt,
    Long version
) {
    public ProfileResponse {
        attributes = attributes != null ? Map.copyOf(attributes) : Map.of();
    }

    /**
     * Factory method to create ProfileResponse from domain Profile entity.
     * 
     * @param profile The domain profile entity
     * @return A ProfileResponse DTO
     */
    public static ProfileResponse from(Profile profile) {
        return new ProfileResponse(
            profile.getId().getValue(),
            profile.getTenantId().getValue(),
            profile.getHandle().getValue(),
            profile.getAttributes(),
            profile.getCreatedAt().toString(),
            profile.getUpdatedAt().toString(),
            profile.getVersion()
        );
    }
}
