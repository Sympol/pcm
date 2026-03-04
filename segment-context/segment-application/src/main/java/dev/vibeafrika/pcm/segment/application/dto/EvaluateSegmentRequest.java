package dev.vibeafrika.pcm.segment.application.dto;

import java.util.UUID;

/**
 * Request DTO for evaluating which segments match a profile.
 * No framework annotations - pure data carrier.
 */
public record EvaluateSegmentRequest(
    UUID profileId,
    String tenantId
) {
    public EvaluateSegmentRequest {
        if (profileId == null) {
            throw new IllegalArgumentException("Profile ID is required");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
    }
}
