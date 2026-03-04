package dev.vibeafrika.pcm.preference.application.usecase;

import dev.vibeafrika.pcm.preference.application.dto.UpdatePreferenceRequest;
import dev.vibeafrika.pcm.preference.application.dto.PreferenceResponse;
import dev.vibeafrika.pcm.preference.application.port.EventPublisher;
import dev.vibeafrika.pcm.preference.domain.event.PreferenceUpdatedEvent;
import dev.vibeafrika.pcm.preference.domain.exception.PreferenceNotFoundException;
import dev.vibeafrika.pcm.preference.domain.model.Preference;
import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import dev.vibeafrika.pcm.preference.domain.repository.PreferenceRepository;

/**
 * Use case for updating preference settings.
 */
public class UpdatePreferenceUseCase {
    private final PreferenceRepository preferenceRepository;
    private final EventPublisher eventPublisher;

    // Constructor injection - no framework annotations
    public UpdatePreferenceUseCase(PreferenceRepository preferenceRepository, EventPublisher eventPublisher) {
        this.preferenceRepository = preferenceRepository;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public PreferenceResponse execute(UpdatePreferenceRequest request) {
        // Load preference by ID
        PreferenceId preferenceId = PreferenceId.of(request.preferenceId());
        
        Preference preference = preferenceRepository.findById(preferenceId)
            .orElseThrow(() -> new PreferenceNotFoundException(preferenceId));

        // Update domain entity (enforces business rules)
        preference.updateSettings(request.settings());

        // Persist
        Preference updatedPreference = preferenceRepository.save(preference);

        // Publish domain event
        PreferenceUpdatedEvent event = PreferenceUpdatedEvent.of(
            updatedPreference.getId(),
            updatedPreference.getTenantId(),
            updatedPreference.getProfileId()
        );
        eventPublisher.publish(event);

        // Return DTO
        return PreferenceResponse.from(updatedPreference);
    }
}
