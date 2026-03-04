package dev.vibeafrika.pcm.segment.application.dto;

import java.util.UUID;

/**
 * Request DTO for retrieving a segment.
 * No framework annotations - pure data carrier.
 */
public record GetSegmentRequest(
    UUID segmentId
) {
    public GetSegmentRequest {
        if (segmentId == null) {
            throw new IllegalArgumentException("Segment ID is required");
        }
    }
}
