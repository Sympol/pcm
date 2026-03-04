package dev.vibeafrika.pcm.consent.application.usecase;

import dev.vibeafrika.pcm.consent.application.port.EventPublisher;
import dev.vibeafrika.pcm.consent.domain.event.ConsentRevokedEvent;
import dev.vibeafrika.pcm.consent.domain.model.Consent;
import dev.vibeafrika.pcm.consent.domain.model.ProfileId;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;

import java.util.List;
import java.util.UUID;

/**
 * Use case for revoking all consents for a profile.
 * Used for GDPR compliance when a profile is deleted.
 * No framework annotations - pure business logic.
 */
public class RevokeConsentsForProfileUseCase {
    private final ConsentRepository consentRepository;
    private final EventPublisher eventPublisher;

    public RevokeConsentsForProfileUseCase(ConsentRepository consentRepository, EventPublisher eventPublisher) {
        this.consentRepository = consentRepository;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Execute the use case - revoke all active consents for a profile.
     * Transaction boundary is defined by this method scope.
     *
     * @param profileId the UUID of the profile whose consents should be revoked
     */
    public void execute(UUID profileId) {
        ProfileId profileIdVO = ProfileId.of(profileId);
        
        // Find all active consents for the profile
        List<Consent> activeConsents = consentRepository.findActiveConsents(profileIdVO);
        
        // Revoke each consent
        for (Consent consent : activeConsents) {
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
        }
    }
}
