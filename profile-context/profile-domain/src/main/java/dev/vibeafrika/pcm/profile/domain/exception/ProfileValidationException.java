package dev.vibeafrika.pcm.profile.domain.exception;

/**
 * Thrown when profile validation fails.
 */
public class ProfileValidationException extends ProfileDomainException {
    
    public ProfileValidationException(String message) {
        super(message);
    }

    public ProfileValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
