package dev.vibeafrika.pcm.segment.domain.exception;

/**
 * Thrown when segment criteria are invalid.
 */
public class InvalidSegmentCriteriaException extends SegmentDomainException {
    public InvalidSegmentCriteriaException(String message) {
        super(message);
    }

    public InvalidSegmentCriteriaException(String message, Throwable cause) {
        super(message, cause);
    }
}
