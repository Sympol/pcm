package dev.vibeafrika.pcm.profile.domain.event;

import dev.vibeafrika.pcm.profile.domain.model.Handle;
import dev.vibeafrika.pcm.profile.domain.model.ProfileId;
import dev.vibeafrika.pcm.profile.domain.model.TenantId;

import java.time.Instant;
import java.util.UUID;

/**
 * Domain event published when a profile is created.
 */
public record ProfileCreatedEvent(
    UUID eventId,
    ProfileId profileId,
    TenantId tenantId,
    Handle handle,
    Instant occurredAt
) {
    /**
     * Factory method to create a ProfileCreatedEvent.
     *
     * @param profileId the ID of the created profile
     * @param tenantId the tenant ID
     * @param handle the profile handle
     * @return a new ProfileCreatedEvent
     */
    public static ProfileCreatedEvent of(ProfileId profileId, TenantId tenantId, Handle handle) {
        return new ProfileCreatedEvent(
            UUID.randomUUID(),
            profileId,
            tenantId,
            handle,
            Instant.now()
        );
    }
}
