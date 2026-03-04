package dev.vibeafrika.pcm.profile.domain.exception;

/**
 * Thrown when a handle is invalid or already taken.
 */
public class InvalidHandleException extends ProfileDomainException {
    
    public InvalidHandleException(String message) {
        super(message);
    }

    public InvalidHandleException(String message, Throwable cause) {
        super(message, cause);
    }
}
