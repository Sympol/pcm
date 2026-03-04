package dev.vibeafrika.pcm.profile.domain.exception;

/**
 * Thrown when attempting to operate on a deleted profile.
 */
public class ProfileDeletedException extends ProfileDomainException {
    
    public ProfileDeletedException(String message) {
        super(message);
    }
}
