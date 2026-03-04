package dev.vibeafrika.pcm.preference.domain.event;

import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import dev.vibeafrika.pcm.preference.domain.model.ProfileId;
import dev.vibeafrika.pcm.preference.domain.model.TenantId;

import java.time.Instant;
import java.util.UUID;

/**
 * Domain event published when a preference is deleted.
 * Framework-agnostic - no Spring or CDI annotations.
 */
public record PreferenceDeletedEvent(
    UUID eventId,
    PreferenceId preferenceId,
    TenantId tenantId,
    ProfileId profileId,
    Instant occurredAt
) {
    /**
     * Factory method to create a PreferenceDeletedEvent.
     *
     * @param preferenceId the ID of the deleted preference
     * @param tenantId the tenant ID
     * @param profileId the profile ID
     * @return a new PreferenceDeletedEvent
     */
    public static PreferenceDeletedEvent of(PreferenceId preferenceId, TenantId tenantId, ProfileId profileId) {
        return new PreferenceDeletedEvent(
            UUID.randomUUID(),
            preferenceId,
            tenantId,
            profileId,
            Instant.now()
        );
    }
}
