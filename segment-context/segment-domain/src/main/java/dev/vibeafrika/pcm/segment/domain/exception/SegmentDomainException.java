package dev.vibeafrika.pcm.segment.domain.exception;

/**
 * Base class for all Segment domain exceptions.
 * Does not extend any framework-specific exception types.
 */
public abstract class SegmentDomainException extends RuntimeException {
    protected SegmentDomainException(String message) {
        super(message);
    }

    protected SegmentDomainException(String message, Throwable cause) {
        super(message, cause);
    }
}
