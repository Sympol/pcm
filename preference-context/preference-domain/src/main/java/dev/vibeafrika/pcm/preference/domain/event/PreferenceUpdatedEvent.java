package dev.vibeafrika.pcm.preference.domain.event;

import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import dev.vibeafrika.pcm.preference.domain.model.ProfileId;
import dev.vibeafrika.pcm.preference.domain.model.TenantId;

import java.time.Instant;
import java.util.UUID;

/**
 * Domain event published when a preference is updated.
 * Framework-agnostic - no Spring or CDI annotations.
 */
public record PreferenceUpdatedEvent(
    UUID eventId,
    PreferenceId preferenceId,
    TenantId tenantId,
    ProfileId profileId,
    Instant occurredAt
) {
    /**
     * Factory method to create a PreferenceUpdatedEvent.
     *
     * @param preferenceId the ID of the updated preference
     * @param tenantId the tenant ID
     * @param profileId the profile ID
     * @return a new PreferenceUpdatedEvent
     */
    public static PreferenceUpdatedEvent of(PreferenceId preferenceId, TenantId tenantId, ProfileId profileId) {
        return new PreferenceUpdatedEvent(
            UUID.randomUUID(),
            preferenceId,
            tenantId,
            profileId,
            Instant.now()
        );
    }
}
