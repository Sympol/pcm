package dev.vibeafrika.pcm.profile.application.usecase;

import dev.vibeafrika.pcm.profile.application.dto.CreateProfileRequest;
import dev.vibeafrika.pcm.profile.application.dto.ProfileResponse;
import dev.vibeafrika.pcm.profile.application.port.EventPublisher;
import dev.vibeafrika.pcm.profile.domain.event.ProfileCreatedEvent;
import dev.vibeafrika.pcm.profile.domain.exception.InvalidHandleException;
import dev.vibeafrika.pcm.profile.domain.model.Handle;
import dev.vibeafrika.pcm.profile.domain.model.Profile;
import dev.vibeafrika.pcm.profile.domain.model.TenantId;
import dev.vibeafrika.pcm.profile.domain.repository.ProfileRepository;

/**
 * Use case for creating a new profile.
 * No framework annotations - pure business logic.
 * 
 * Business rules:
 * - Handle must be unique within the tenant
 * - Profile is created with provided attributes
 */
public class CreateProfileUseCase {
    private final ProfileRepository profileRepository;
    private final EventPublisher eventPublisher;

    /**
     * Constructor injection - no framework annotations.
     * 
     * @param profileRepository The profile repository
     * @param eventPublisher The event publisher
     */
    public CreateProfileUseCase(ProfileRepository profileRepository, EventPublisher eventPublisher) {
        this.profileRepository = profileRepository;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     * 
     * @param request The create profile request
     * @return The created profile response
     * @throws InvalidHandleException if handle is already taken
     */
    public ProfileResponse execute(CreateProfileRequest request) {
        // Validate handle is not taken
        Handle handle = Handle.of(request.handle());
        TenantId tenantId = TenantId.of(request.tenantId());
        
        if (profileRepository.existsByHandle(handle, tenantId)) {
            throw new InvalidHandleException("Handle already taken: " + handle);
        }

        // Create domain entity
        Profile profile = Profile.create(tenantId, handle, request.attributes());

        // Persist
        Profile savedProfile = profileRepository.save(profile);

        // Publish domain event
        ProfileCreatedEvent event = ProfileCreatedEvent.of(
            savedProfile.getId(),
            savedProfile.getTenantId(),
            savedProfile.getHandle()
        );
        eventPublisher.publish(event);

        // Return DTO
        return ProfileResponse.from(savedProfile);
    }
}
