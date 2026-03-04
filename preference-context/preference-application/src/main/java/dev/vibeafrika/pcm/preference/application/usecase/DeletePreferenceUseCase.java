package dev.vibeafrika.pcm.preference.application.usecase;

import dev.vibeafrika.pcm.preference.application.dto.DeletePreferenceRequest;
import dev.vibeafrika.pcm.preference.application.port.EventPublisher;
import dev.vibeafrika.pcm.preference.domain.event.PreferenceDeletedEvent;
import dev.vibeafrika.pcm.preference.domain.exception.PreferenceNotFoundException;
import dev.vibeafrika.pcm.preference.domain.model.Preference;
import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import dev.vibeafrika.pcm.preference.domain.repository.PreferenceRepository;

/**
 * Use case for deleting a preference (soft delete).
 */
public class DeletePreferenceUseCase {
    private final PreferenceRepository preferenceRepository;
    private final EventPublisher eventPublisher;

    // Constructor injection - no framework annotations
    public DeletePreferenceUseCase(PreferenceRepository preferenceRepository, EventPublisher eventPublisher) {
        this.preferenceRepository = preferenceRepository;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public void execute(DeletePreferenceRequest request) {
        // Load preference by ID
        PreferenceId preferenceId = PreferenceId.of(request.preferenceId());
        
        Preference preference = preferenceRepository.findById(preferenceId)
            .orElseThrow(() -> new PreferenceNotFoundException(preferenceId));

        // Soft delete domain entity
        preference.delete();

        // Persist
        Preference deletedPreference = preferenceRepository.save(preference);

        // Publish domain event
        PreferenceDeletedEvent event = PreferenceDeletedEvent.of(
            deletedPreference.getId(),
            deletedPreference.getTenantId(),
            deletedPreference.getProfileId()
        );
        eventPublisher.publish(event);
    }
}
