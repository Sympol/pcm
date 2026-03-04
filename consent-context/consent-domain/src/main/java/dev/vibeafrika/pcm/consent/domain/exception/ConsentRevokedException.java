package dev.vibeafrika.pcm.consent.domain.exception;

/**
 * Thrown when attempting to operate on a revoked consent.
 */
public class ConsentRevokedException extends ConsentDomainException {
    public ConsentRevokedException(String message) {
        super(message);
    }
}
