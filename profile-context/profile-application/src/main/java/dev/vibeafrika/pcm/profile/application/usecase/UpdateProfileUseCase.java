package dev.vibeafrika.pcm.profile.application.usecase;

import dev.vibeafrika.pcm.profile.application.dto.ProfileResponse;
import dev.vibeafrika.pcm.profile.application.dto.UpdateProfileRequest;
import dev.vibeafrika.pcm.profile.application.port.EventPublisher;
import dev.vibeafrika.pcm.profile.domain.event.ProfileUpdatedEvent;
import dev.vibeafrika.pcm.profile.domain.exception.ProfileNotFoundException;
import dev.vibeafrika.pcm.profile.domain.model.Profile;
import dev.vibeafrika.pcm.profile.domain.model.ProfileId;
import dev.vibeafrika.pcm.profile.domain.model.TenantId;
import dev.vibeafrika.pcm.profile.domain.repository.ProfileRepository;

/**
 * Use case for updating profile attributes.
 * No framework annotations - pure business logic.
 * 
 * Business rules:
 * - Profile must exist and belong to the tenant
 * - Cannot update deleted profiles (enforced by domain entity)
 */
public class UpdateProfileUseCase {
    private final ProfileRepository profileRepository;
    private final EventPublisher eventPublisher;

    /**
     * Constructor injection - no framework annotations.
     * 
     * @param profileRepository The profile repository
     * @param eventPublisher The event publisher
     */
    public UpdateProfileUseCase(ProfileRepository profileRepository, EventPublisher eventPublisher) {
        this.profileRepository = profileRepository;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     * 
     * @param request The update profile request
     * @return The updated profile response
     * @throws ProfileNotFoundException if profile not found
     */
    public ProfileResponse execute(UpdateProfileRequest request) {
        // Load profile
        ProfileId profileId = ProfileId.of(request.profileId());
        TenantId tenantId = TenantId.of(request.tenantId());
        
        Profile profile = profileRepository.findByIdAndTenant(profileId, tenantId)
            .orElseThrow(() -> new ProfileNotFoundException(profileId));

        // Update domain entity (enforces business rules)
        profile.updateAttributes(request.attributes());

        // Persist
        Profile updatedProfile = profileRepository.save(profile);

        // Publish domain event
        ProfileUpdatedEvent event = ProfileUpdatedEvent.of(
            updatedProfile.getId(),
            updatedProfile.getTenantId(),
            updatedProfile.getHandle()
        );
        eventPublisher.publish(event);

        // Return DTO
        return ProfileResponse.from(updatedProfile);
    }
}
