package dev.vibeafrika.pcm.segment.infrastructure.external;

import dev.vibeafrika.pcm.profile.domain.repository.ProfileRepository;
import dev.vibeafrika.pcm.segment.application.port.ProfileProvider;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

/**
 * Adapter that provides profile data from the profile context to the segment context.
 */
@Component("segmentExternalProfileAdapter")
public class ExternalProfileAdapter implements ProfileProvider {

    private final ProfileRepository profileRepository;

    public ExternalProfileAdapter(ProfileRepository profileRepository) {
        this.profileRepository = profileRepository;
    }

    @Override
    public Optional<ProfileSnapshot> getProfileSnapshot(UUID profileId) {
        return profileRepository.findById(dev.vibeafrika.pcm.profile.domain.model.ProfileId.of(profileId))
                .map(profile -> new ProfileSnapshot(
                        profile.getId().getValue(),
                        profile.getHandle().getValue(),
                        profile.getAttributes()
                ));
    }
}
