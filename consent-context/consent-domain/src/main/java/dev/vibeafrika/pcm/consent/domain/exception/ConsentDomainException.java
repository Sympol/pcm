package dev.vibeafrika.pcm.consent.domain.exception;

/**
 * Base class for all consent domain exceptions.
 * Does not extend any framework-specific exception types.
 */
public abstract class ConsentDomainException extends RuntimeException {
    protected ConsentDomainException(String message) {
        super(message);
    }

    protected ConsentDomainException(String message, Throwable cause) {
        super(message, cause);
    }
}
