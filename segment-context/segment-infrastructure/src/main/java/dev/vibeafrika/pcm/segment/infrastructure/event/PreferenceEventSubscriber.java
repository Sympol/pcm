package dev.vibeafrika.pcm.segment.infrastructure.event;

import dev.vibeafrika.pcm.preference.domain.event.PreferenceCreatedEvent;
import dev.vibeafrika.pcm.preference.domain.event.PreferenceUpdatedEvent;
import dev.vibeafrika.pcm.segment.application.usecase.EvaluateSegmentForPreferenceUseCase;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Event subscriber for Preference context events.
 * Listens to preference events and triggers segment evaluation.
 * Uses Spring's event mechanism for synchronous, transactional event delivery.
 */
@Component
public class PreferenceEventSubscriber {
    
    private final EvaluateSegmentForPreferenceUseCase evaluateSegmentUseCase;

    public PreferenceEventSubscriber(EvaluateSegmentForPreferenceUseCase evaluateSegmentUseCase) {
        this.evaluateSegmentUseCase = evaluateSegmentUseCase;
    }

    /**
     * Handle PreferenceCreatedEvent.
     * Uses @TransactionalEventListener to ensure event is delivered within the same transaction.
     * If the transaction rolls back, this handler will not be invoked.
     *
     * @param event the preference created event
     */
    @TransactionalEventListener
    public void onPreferenceCreated(PreferenceCreatedEvent event) {
        // Delegate to use case for business logic
        evaluateSegmentUseCase.execute(
            event.profileId().getValue(),
            event.tenantId().getValue()
        );
    }

    /**
     * Handle PreferenceUpdatedEvent.
     * Uses @TransactionalEventListener to ensure event is delivered within the same transaction.
     * If the transaction rolls back, this handler will not be invoked.
     *
     * @param event the preference updated event
     */
    @TransactionalEventListener
    public void onPreferenceUpdated(PreferenceUpdatedEvent event) {
        // Delegate to use case for business logic
        evaluateSegmentUseCase.execute(
            event.profileId().getValue(),
            event.tenantId().getValue()
        );
    }
}
