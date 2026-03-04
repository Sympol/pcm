package dev.vibeafrika.pcm.preference.domain.exception;

/**
 * Thrown when attempting to operate on a deleted preference.
 */
public class PreferenceDeletedException extends PreferenceDomainException {
    public PreferenceDeletedException(String message) {
        super(message);
    }
}
