package dev.vibeafrika.pcm.profile.application.usecase;

import dev.vibeafrika.pcm.profile.application.dto.EraseProfileRequest;
import dev.vibeafrika.pcm.profile.application.dto.ProfileResponse;
import dev.vibeafrika.pcm.profile.application.port.EventPublisher;
import dev.vibeafrika.pcm.profile.domain.event.ProfileDeletedEvent;
import dev.vibeafrika.pcm.profile.domain.exception.ProfileNotFoundException;
import dev.vibeafrika.pcm.profile.domain.model.Profile;
import dev.vibeafrika.pcm.profile.domain.model.ProfileId;
import dev.vibeafrika.pcm.profile.domain.model.TenantId;
import dev.vibeafrika.pcm.profile.domain.repository.ProfileRepository;

/**
 * Use case for erasing a profile (GDPR compliance).
 * No framework annotations - pure business logic.
 * 
 * Business rules:
 * - Profile must exist and belong to the tenant
 * - Erasure performs soft delete and anonymizes data
 * - All attributes are cleared
 * - Handle is anonymized
 */
public class EraseProfileUseCase {
    private final ProfileRepository profileRepository;
    private final EventPublisher eventPublisher;

    /**
     * Constructor injection - no framework annotations.
     * 
     * @param profileRepository The profile repository
     * @param eventPublisher The event publisher
     */
    public EraseProfileUseCase(ProfileRepository profileRepository, EventPublisher eventPublisher) {
        this.profileRepository = profileRepository;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     * 
     * @param request The erase profile request
     * @return The erased profile response
     * @throws ProfileNotFoundException if profile not found
     */
    public ProfileResponse execute(EraseProfileRequest request) {
        // Load profile
        ProfileId profileId = ProfileId.of(request.profileId());
        TenantId tenantId = TenantId.of(request.tenantId());
        
        Profile profile = profileRepository.findByIdAndTenant(profileId, tenantId)
            .orElseThrow(() -> new ProfileNotFoundException(profileId));

        // Erase domain entity (soft delete + anonymize)
        profile.erase();

        // Persist
        Profile erasedProfile = profileRepository.save(profile);

        // Publish domain event
        ProfileDeletedEvent event = ProfileDeletedEvent.of(
            erasedProfile.getId(),
            erasedProfile.getTenantId(),
            erasedProfile.getHandle()
        );
        eventPublisher.publish(event);

        // Return DTO
        return ProfileResponse.from(erasedProfile);
    }
}
