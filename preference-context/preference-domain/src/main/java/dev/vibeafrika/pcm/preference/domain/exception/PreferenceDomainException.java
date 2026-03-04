package dev.vibeafrika.pcm.preference.domain.exception;

/**
 * Base class for all preference domain exceptions.
 * Does not extend any framework-specific exception types.
 */
public abstract class PreferenceDomainException extends RuntimeException {
    protected PreferenceDomainException(String message) {
        super(message);
    }

    protected PreferenceDomainException(String message, Throwable cause) {
        super(message, cause);
    }
}
