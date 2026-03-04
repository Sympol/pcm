package dev.vibeafrika.pcm.consent.domain.exception;

/**
 * Thrown when IAB TCF validation fails.
 */
public class TCFValidationException extends ConsentDomainException {
    public TCFValidationException(String message) {
        super(message);
    }

    public TCFValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
