package dev.vibeafrika.pcm.consent.application.usecase;

import dev.vibeafrika.pcm.consent.domain.exception.ConsentNotFoundException;
import dev.vibeafrika.pcm.consent.domain.model.*;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;

/**
 * Use case for verifying consent.
 * No framework annotations - pure business logic.
 */
public class VerifyConsentUseCase {
    private final ConsentRepository consentRepository;

    public VerifyConsentUseCase(ConsentRepository consentRepository) {
        this.consentRepository = consentRepository;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public boolean execute(ConsentId consentId) {
        Consent consent = consentRepository.findById(consentId)
            .orElseThrow(() -> new ConsentNotFoundException(consentId));

        return consent.verify();
    }
}
