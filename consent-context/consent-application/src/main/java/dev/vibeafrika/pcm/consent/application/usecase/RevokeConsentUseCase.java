package dev.vibeafrika.pcm.consent.application.usecase;

import dev.vibeafrika.pcm.consent.application.dto.ConsentResponse;
import dev.vibeafrika.pcm.consent.application.dto.RevokeConsentRequest;
import dev.vibeafrika.pcm.consent.application.port.EventPublisher;
import dev.vibeafrika.pcm.consent.domain.event.ConsentRevokedEvent;
import dev.vibeafrika.pcm.consent.domain.exception.ConsentNotFoundException;
import dev.vibeafrika.pcm.consent.domain.model.Consent;
import dev.vibeafrika.pcm.consent.domain.model.ConsentId;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;

/**
 * Use case for revoking consent.
 * No framework annotations - pure business logic.
 */
public class RevokeConsentUseCase {
    private final ConsentRepository consentRepository;
    private final EventPublisher eventPublisher;

    public RevokeConsentUseCase(ConsentRepository consentRepository, EventPublisher eventPublisher) {
        this.consentRepository = consentRepository;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public ConsentResponse execute(RevokeConsentRequest request) {
        ConsentId consentId = ConsentId.of(request.consentId());
        
        Consent consent = consentRepository.findById(consentId)
            .orElseThrow(() -> new ConsentNotFoundException(consentId));

        // Revoke consent (adds revocation event to ledger)
        consent.revoke();

        // Persist
        Consent revokedConsent = consentRepository.save(consent);

        // Publish domain event (important audit trail entry)
        ConsentRevokedEvent event = ConsentRevokedEvent.of(
            revokedConsent.getId(),
            revokedConsent.getProfileId(),
            revokedConsent.getTenantId(),
            revokedConsent.getPurpose()
        );
        eventPublisher.publish(event);

        return ConsentResponse.from(revokedConsent);
    }
}
