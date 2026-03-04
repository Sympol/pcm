package dev.vibeafrika.pcm.preference.domain.exception;

/**
 * Thrown when preference validation fails.
 */
public class PreferenceValidationException extends PreferenceDomainException {
    public PreferenceValidationException(String message) {
        super(message);
    }
}
