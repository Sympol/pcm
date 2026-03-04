package dev.vibeafrika.pcm.preference.application.usecase;

import dev.vibeafrika.pcm.preference.application.dto.CreatePreferenceRequest;
import dev.vibeafrika.pcm.preference.application.dto.PreferenceResponse;
import dev.vibeafrika.pcm.preference.application.port.EventPublisher;
import dev.vibeafrika.pcm.preference.domain.event.PreferenceCreatedEvent;
import dev.vibeafrika.pcm.preference.domain.model.Preference;
import dev.vibeafrika.pcm.preference.domain.model.ProfileId;
import dev.vibeafrika.pcm.preference.domain.model.TenantId;
import dev.vibeafrika.pcm.preference.domain.repository.PreferenceRepository;

/**
 * Use case for creating a new preference.
 */
public class CreatePreferenceUseCase {
    private final PreferenceRepository preferenceRepository;
    private final EventPublisher eventPublisher;

    // Constructor injection - no framework annotations
    public CreatePreferenceUseCase(PreferenceRepository preferenceRepository, EventPublisher eventPublisher) {
        this.preferenceRepository = preferenceRepository;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public PreferenceResponse execute(CreatePreferenceRequest request) {
        // Create domain value objects
        TenantId tenantId = TenantId.of(request.tenantId());
        ProfileId profileId = ProfileId.of(request.profileId());

        // Create domain entity
        Preference preference = Preference.create(tenantId, profileId, request.settings());

        // Persist
        Preference savedPreference = preferenceRepository.save(preference);

        // Publish domain event
        PreferenceCreatedEvent event = PreferenceCreatedEvent.of(
            savedPreference.getId(),
            savedPreference.getTenantId(),
            savedPreference.getProfileId()
        );
        eventPublisher.publish(event);

        // Return DTO
        return PreferenceResponse.from(savedPreference);
    }
}
