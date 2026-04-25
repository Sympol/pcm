package dev.vibeafrika.pcm.segment.application.dto;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Request DTO for updating a segment.
 * No framework annotations - pure data carrier.
 */
public record UpdateSegmentRequest(
    UUID segmentId,
    Set<String> tags,
    Map<String, Double> scores
) {
    public UpdateSegmentRequest {
    }
}
