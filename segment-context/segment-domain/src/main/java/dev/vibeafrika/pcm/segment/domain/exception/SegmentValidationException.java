package dev.vibeafrika.pcm.segment.domain.exception;

/**
 * Thrown when segment validation fails.
 */
public class SegmentValidationException extends SegmentDomainException {
    public SegmentValidationException(String message) {
        super(message);
    }

    public SegmentValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
