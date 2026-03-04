package dev.vibeafrika.pcm.consent.domain.exception;

/**
 * Thrown when a consent purpose is invalid.
 */
public class InvalidConsentPurposeException extends ConsentDomainException {
    public InvalidConsentPurposeException(String message) {
        super(message);
    }
}
