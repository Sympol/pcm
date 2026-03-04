package dev.vibeafrika.pcm.consent.infrastructure.event;

import dev.vibeafrika.pcm.consent.application.usecase.RevokeConsentsForProfileUseCase;
import dev.vibeafrika.pcm.profile.domain.event.ProfileDeletedEvent;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Event subscriber for Profile context events.
 * Listens to profile deletion events and automatically revokes consents for GDPR compliance.
 * Uses Spring's event mechanism for synchronous, transactional event delivery.
 */
@Component
public class ProfileEventSubscriber {
    
    private final RevokeConsentsForProfileUseCase revokeConsentsUseCase;

    public ProfileEventSubscriber(RevokeConsentsForProfileUseCase revokeConsentsUseCase) {
        this.revokeConsentsUseCase = revokeConsentsUseCase;
    }

    /**
     * Handle ProfileDeletedEvent.
     * Uses @TransactionalEventListener to ensure event is delivered within the same transaction.
     * If the transaction rolls back, this handler will not be invoked.
     * 
     * When a profile is deleted (GDPR erasure), all active consents for that profile
     * must be automatically revoked to maintain compliance.
     *
     * @param event the profile deleted event
     */
    @TransactionalEventListener
    public void onProfileDeleted(ProfileDeletedEvent event) {
        // Delegate to use case for business logic
        revokeConsentsUseCase.execute(event.profileId().getValue());
    }
}
