package dev.vibeafrika.pcm.consent.application.usecase;

import dev.vibeafrika.pcm.consent.application.dto.ConsentResponse;
import dev.vibeafrika.pcm.consent.application.dto.GrantConsentRequest;
import dev.vibeafrika.pcm.consent.application.port.EventPublisher;
import dev.vibeafrika.pcm.consent.domain.event.ConsentGrantedEvent;
import dev.vibeafrika.pcm.consent.domain.model.*;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;

/**
 * Use case for granting consent.
 * No framework annotations - pure business logic.
 */
public class GrantConsentUseCase {
    private final ConsentRepository consentRepository;
    private final EventPublisher eventPublisher;

    public GrantConsentUseCase(ConsentRepository consentRepository, EventPublisher eventPublisher) {
        this.consentRepository = consentRepository;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public ConsentResponse execute(GrantConsentRequest request) {
        // Create domain objects
        ProfileId profileId = ProfileId.of(request.profileId());
        TenantId tenantId = TenantId.of(request.tenantId());
        ConsentPurpose purpose = ConsentPurpose.of(request.purpose());
        ConsentScope scope = ConsentScope.of(request.scope());

        // Create consent entity
        Consent consent = Consent.create(profileId, tenantId, purpose, scope);

        // Persist
        Consent savedConsent = consentRepository.save(consent);

        // Publish domain event (important audit trail entry)
        ConsentGrantedEvent event = ConsentGrantedEvent.of(
            savedConsent.getId(),
            savedConsent.getProfileId(),
            savedConsent.getTenantId(),
            savedConsent.getPurpose(),
            savedConsent.getScope()
        );
        eventPublisher.publish(event);

        return ConsentResponse.from(savedConsent);
    }
}
