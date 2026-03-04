package dev.vibeafrika.pcm.consent.domain.exception;

import dev.vibeafrika.pcm.consent.domain.model.ConsentId;

/**
 * Thrown when a consent is not found.
 */
public class ConsentNotFoundException extends ConsentDomainException {
    private final ConsentId consentId;

    public ConsentNotFoundException(ConsentId consentId) {
        super("Consent not found: " + consentId);
        this.consentId = consentId;
    }

    public ConsentId getConsentId() {
        return consentId;
    }
}
