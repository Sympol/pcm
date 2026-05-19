package dev.vibeafrika.pcm.segment.application.dto;

import dev.vibeafrika.pcm.segment.domain.model.Segment;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Response DTO for segment operations.
 * No framework annotations - pure data carrier.
 */
public record SegmentResponse(
    UUID id,
    String tenantId,
    UUID profileId,
    Set<String> tags,
    Map<String, Double> scores,
    Instant lastUpdated
) {
    public SegmentResponse {
        tags = tags != null ? Set.copyOf(tags) : Set.of();
        scores = scores != null ? Map.copyOf(scores) : Map.of();
    }

    /**
     * Factory method to create a SegmentResponse from a domain Segment entity.
     */
    public static SegmentResponse from(Segment segment) {
        return new SegmentResponse(
            segment.getId().getValue(),
            segment.getTenantId().getValue(),
            segment.getProfileId().getValue(),
            segment.getTags(),
            segment.getScores(),
            segment.getLastUpdated()
        );
    }
}
