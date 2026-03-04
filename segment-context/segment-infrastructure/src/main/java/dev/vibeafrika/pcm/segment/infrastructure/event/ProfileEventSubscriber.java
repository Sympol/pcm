package dev.vibeafrika.pcm.segment.infrastructure.event;

import dev.vibeafrika.pcm.profile.domain.event.ProfileCreatedEvent;
import dev.vibeafrika.pcm.profile.domain.event.ProfileUpdatedEvent;
import dev.vibeafrika.pcm.segment.application.usecase.EvaluateSegmentForProfileUseCase;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Event subscriber for Profile context events.
 * Listens to profile events and triggers segment evaluation.
 * Uses Spring's event mechanism for synchronous, transactional event delivery.
 */
@Component
public class ProfileEventSubscriber {
    
    private final EvaluateSegmentForProfileUseCase evaluateSegmentUseCase;

    public ProfileEventSubscriber(EvaluateSegmentForProfileUseCase evaluateSegmentUseCase) {
        this.evaluateSegmentUseCase = evaluateSegmentUseCase;
    }

    /**
     * Handle ProfileCreatedEvent.
     * Uses @TransactionalEventListener to ensure event is delivered within the same transaction.
     * If the transaction rolls back, this handler will not be invoked.
     *
     * @param event the profile created event
     */
    @TransactionalEventListener
    public void onProfileCreated(ProfileCreatedEvent event) {
        // Delegate to use case for business logic
        evaluateSegmentUseCase.execute(
            event.profileId().getValue(),
            event.tenantId().getValue()
        );
    }

    /**
     * Handle ProfileUpdatedEvent.
     * Uses @TransactionalEventListener to ensure event is delivered within the same transaction.
     * If the transaction rolls back, this handler will not be invoked.
     *
     * @param event the profile updated event
     */
    @TransactionalEventListener
    public void onProfileUpdated(ProfileUpdatedEvent event) {
        // Delegate to use case for business logic
        evaluateSegmentUseCase.execute(
            event.profileId().getValue(),
            event.tenantId().getValue()
        );
    }
}
