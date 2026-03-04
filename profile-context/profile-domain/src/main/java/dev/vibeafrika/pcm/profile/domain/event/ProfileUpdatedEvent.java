package dev.vibeafrika.pcm.profile.domain.event;

import dev.vibeafrika.pcm.profile.domain.model.Handle;
import dev.vibeafrika.pcm.profile.domain.model.ProfileId;
import dev.vibeafrika.pcm.profile.domain.model.TenantId;

import java.time.Instant;
import java.util.UUID;

/**
 * Domain event published when a profile is updated.
 */
public record ProfileUpdatedEvent(
    UUID eventId,
    ProfileId profileId,
    TenantId tenantId,
    Handle handle,
    Instant occurredAt
) {
    /**
     * Factory method to create a ProfileUpdatedEvent.
     *
     * @param profileId the ID of the updated profile
     * @param tenantId the tenant ID
     * @param handle the profile handle
     * @return a new ProfileUpdatedEvent
     */
    public static ProfileUpdatedEvent of(ProfileId profileId, TenantId tenantId, Handle handle) {
        return new ProfileUpdatedEvent(
            UUID.randomUUID(),
            profileId,
            tenantId,
            handle,
            Instant.now()
        );
    }
}
