package dev.vibeafrika.pcm.consent.domain.event;

import dev.vibeafrika.pcm.consent.domain.model.ConsentId;
import dev.vibeafrika.pcm.consent.domain.model.ConsentPurpose;
import dev.vibeafrika.pcm.consent.domain.model.ProfileId;
import dev.vibeafrika.pcm.consent.domain.model.TenantId;

import java.time.Instant;
import java.util.UUID;

/**
 * Domain event published when consent is revoked.
 * Framework-agnostic - no Spring or CDI annotations.
 * Represents an important audit trail entry in the consent ledger.
 */
public record ConsentRevokedEvent(
    UUID eventId,
    ConsentId consentId,
    ProfileId profileId,
    TenantId tenantId,
    ConsentPurpose purpose,
    Instant occurredAt
) {
    /**
     * Factory method to create a ConsentRevokedEvent.
     *
     * @param consentId the ID of the revoked consent
     * @param profileId the profile ID
     * @param tenantId the tenant ID
     * @param purpose the consent purpose
     * @return a new ConsentRevokedEvent
     */
    public static ConsentRevokedEvent of(ConsentId consentId, ProfileId profileId, TenantId tenantId,
                                          ConsentPurpose purpose) {
        return new ConsentRevokedEvent(
            UUID.randomUUID(),
            consentId,
            profileId,
            tenantId,
            purpose,
            Instant.now()
        );
    }
}
