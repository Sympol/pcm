package dev.vibeafrika.pcm.profile.domain.exception;

import dev.vibeafrika.pcm.profile.domain.model.ProfileId;

/**
 * Thrown when a profile is not found.
 */
public class ProfileNotFoundException extends ProfileDomainException {
    private final ProfileId profileId;

    public ProfileNotFoundException(ProfileId profileId) {
        super("Profile not found: " + profileId);
        this.profileId = profileId;
    }

    public ProfileId getProfileId() {
        return profileId;
    }
}
