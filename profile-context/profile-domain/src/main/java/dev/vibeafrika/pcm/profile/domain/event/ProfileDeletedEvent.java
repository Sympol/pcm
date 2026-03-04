package dev.vibeafrika.pcm.profile.domain.event;

import dev.vibeafrika.pcm.profile.domain.model.Handle;
import dev.vibeafrika.pcm.profile.domain.model.ProfileId;
import dev.vibeafrika.pcm.profile.domain.model.TenantId;

import java.time.Instant;
import java.util.UUID;

/**
 * Domain event published when a profile is deleted (GDPR erasure).
 */
public record ProfileDeletedEvent(
    UUID eventId,
    ProfileId profileId,
    TenantId tenantId,
    Handle handle,
    Instant occurredAt
) {
    /**
     * Factory method to create a ProfileDeletedEvent.
     *
     * @param profileId the ID of the deleted profile
     * @param tenantId the tenant ID
     * @param handle the anonymized profile handle
     * @return a new ProfileDeletedEvent
     */
    public static ProfileDeletedEvent of(ProfileId profileId, TenantId tenantId, Handle handle) {
        return new ProfileDeletedEvent(
            UUID.randomUUID(),
            profileId,
            tenantId,
            handle,
            Instant.now()
        );
    }
}
