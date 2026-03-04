package dev.vibeafrika.pcm.segment.domain.exception;

import dev.vibeafrika.pcm.segment.domain.model.SegmentId;

/**
 * Thrown when a segment is not found.
 */
public class SegmentNotFoundException extends SegmentDomainException {
    private final SegmentId segmentId;

    public SegmentNotFoundException(SegmentId segmentId) {
        super("Segment not found: " + segmentId);
        this.segmentId = segmentId;
    }

    public SegmentNotFoundException(String message) {
        super(message);
        this.segmentId = null;
    }

    public SegmentId getSegmentId() {
        return segmentId;
    }
}
