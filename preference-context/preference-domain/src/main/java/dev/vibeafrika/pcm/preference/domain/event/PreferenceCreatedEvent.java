package dev.vibeafrika.pcm.preference.domain.event;

import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import dev.vibeafrika.pcm.preference.domain.model.ProfileId;
import dev.vibeafrika.pcm.preference.domain.model.TenantId;

import java.time.Instant;
import java.util.UUID;

/**
 * Domain event published when a preference is created.
 * Framework-agnostic - no Spring or CDI annotations.
 */
public record PreferenceCreatedEvent(
    UUID eventId,
    PreferenceId preferenceId,
    TenantId tenantId,
    ProfileId profileId,
    Instant occurredAt
) {
    /**
     * Factory method to create a PreferenceCreatedEvent.
     *
     * @param preferenceId the ID of the created preference
     * @param tenantId the tenant ID
     * @param profileId the profile ID
     * @return a new PreferenceCreatedEvent
     */
    public static PreferenceCreatedEvent of(PreferenceId preferenceId, TenantId tenantId, ProfileId profileId) {
        return new PreferenceCreatedEvent(
            UUID.randomUUID(),
            preferenceId,
            tenantId,
            profileId,
            Instant.now()
        );
    }
}
