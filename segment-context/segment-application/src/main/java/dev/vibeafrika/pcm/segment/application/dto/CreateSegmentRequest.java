package dev.vibeafrika.pcm.segment.application.dto;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Request DTO for creating a segment.
 * No framework annotations - pure data carrier.
 */
public record CreateSegmentRequest(
    String tenantId,
    UUID profileId,
    Set<String> tags,
    Map<String, Double> scores
) {
    public CreateSegmentRequest {
        if (profileId == null) {
            throw new IllegalArgumentException("Profile ID is required");
        }
    }
}
