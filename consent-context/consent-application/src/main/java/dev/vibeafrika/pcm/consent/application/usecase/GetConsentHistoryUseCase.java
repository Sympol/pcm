package dev.vibeafrika.pcm.consent.application.usecase;

import dev.vibeafrika.pcm.consent.application.dto.ConsentHistoryResponse;
import dev.vibeafrika.pcm.consent.domain.exception.ConsentNotFoundException;
import dev.vibeafrika.pcm.consent.domain.model.Consent;
import dev.vibeafrika.pcm.consent.domain.model.ConsentId;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;

/**
 * Use case for getting consent history.
 * No framework annotations - pure business logic.
 */
public class GetConsentHistoryUseCase {
    private final ConsentRepository consentRepository;

    public GetConsentHistoryUseCase(ConsentRepository consentRepository) {
        this.consentRepository = consentRepository;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public ConsentHistoryResponse execute(ConsentId consentId) {
        Consent consent = consentRepository.findById(consentId)
            .orElseThrow(() -> new ConsentNotFoundException(consentId));

        return ConsentHistoryResponse.from(consent);
    }
}
