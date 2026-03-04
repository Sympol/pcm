package dev.vibeafrika.pcm.profile.application.usecase;

import dev.vibeafrika.pcm.profile.application.dto.GetProfileRequest;
import dev.vibeafrika.pcm.profile.application.dto.ProfileResponse;
import dev.vibeafrika.pcm.profile.domain.exception.ProfileNotFoundException;
import dev.vibeafrika.pcm.profile.domain.model.Profile;
import dev.vibeafrika.pcm.profile.domain.model.ProfileId;
import dev.vibeafrika.pcm.profile.domain.model.TenantId;
import dev.vibeafrika.pcm.profile.domain.repository.ProfileRepository;

/**
 * Use case for retrieving a profile by ID.
 * No framework annotations - pure business logic.
 * 
 * Business rules:
 * - Profile must exist and belong to the tenant
 */
public class GetProfileUseCase {
    private final ProfileRepository profileRepository;

    /**
     * Constructor injection - no framework annotations.
     * 
     * @param profileRepository The profile repository
     */
    public GetProfileUseCase(ProfileRepository profileRepository) {
        this.profileRepository = profileRepository;
    }

    /**
     * Execute the use case.
     * 
     * @param request The get profile request
     * @return The profile response
     * @throws ProfileNotFoundException if profile not found
     */
    public ProfileResponse execute(GetProfileRequest request) {
        // Load profile
        ProfileId profileId = ProfileId.of(request.profileId());
        TenantId tenantId = TenantId.of(request.tenantId());
        
        Profile profile = profileRepository.findByIdAndTenant(profileId, tenantId)
            .orElseThrow(() -> new ProfileNotFoundException(profileId));

        // Return DTO
        return ProfileResponse.from(profile);
    }
}
