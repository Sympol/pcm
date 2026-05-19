package dev.vibeafrika.pcm.segment.application.port;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Port for retrieving profile data from the profile bounded context.
 * Used for segment evaluation.
 */
public interface ProfileProvider {
    
    /**
     * Get a snapshot of profile data for evaluation.
     * @param profileId the profile identifier
     * @return an optional snapshot containing attributes
     */
    Optional<ProfileSnapshot> getProfileSnapshot(UUID profileId);

    /**
     * Simple DTO for profile data used in evaluation.
     */
    record ProfileSnapshot(
        UUID profileId,
        String handle,
        Map<String, Object> attributes
    ) {
        public ProfileSnapshot {
            attributes = attributes != null ? Map.copyOf(attributes) : Map.of();
        }
    }
}
