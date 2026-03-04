package dev.vibeafrika.pcm.segment.application.dto;

import java.util.UUID;

/**
 * Request DTO for deleting a segment.
 * No framework annotations - pure data carrier.
 */
public record DeleteSegmentRequest(
    UUID segmentId
) {
    public DeleteSegmentRequest {
        if (segmentId == null) {
            throw new IllegalArgumentException("Segment ID is required");
        }
    }
}
