package dev.vibeafrika.pcm.profile.domain.exception;

/**
 * Base class for all Profile domain exceptions.
 */
public abstract class ProfileDomainException extends RuntimeException {
    
    protected ProfileDomainException(String message) {
        super(message);
    }

    protected ProfileDomainException(String message, Throwable cause) {
        super(message, cause);
    }
}
