package dev.vibeafrika.pcm.consent.domain.event;

import dev.vibeafrika.pcm.consent.domain.model.ConsentId;
import dev.vibeafrika.pcm.consent.domain.model.ConsentPurpose;
import dev.vibeafrika.pcm.consent.domain.model.ConsentScope;
import dev.vibeafrika.pcm.consent.domain.model.ProfileId;
import dev.vibeafrika.pcm.consent.domain.model.TenantId;

import java.time.Instant;
import java.util.UUID;

/**
 * Domain event published when consent is granted.
 * Framework-agnostic - no Spring or CDI annotations.
 * Represents an important audit trail entry in the consent ledger.
 */
public record ConsentGrantedEvent(
    UUID eventId,
    ConsentId consentId,
    ProfileId profileId,
    TenantId tenantId,
    ConsentPurpose purpose,
    ConsentScope scope,
    Instant occurredAt
) {
    /**
     * Factory method to create a ConsentGrantedEvent.
     *
     * @param consentId the ID of the granted consent
     * @param profileId the profile ID
     * @param tenantId the tenant ID
     * @param purpose the consent purpose
     * @param scope the consent scope
     * @return a new ConsentGrantedEvent
     */
    public static ConsentGrantedEvent of(ConsentId consentId, ProfileId profileId, TenantId tenantId,
                                          ConsentPurpose purpose, ConsentScope scope) {
        return new ConsentGrantedEvent(
            UUID.randomUUID(),
            consentId,
            profileId,
            tenantId,
            purpose,
            scope,
            Instant.now()
        );
    }
}
