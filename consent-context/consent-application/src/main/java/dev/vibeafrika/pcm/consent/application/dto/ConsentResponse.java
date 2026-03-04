package dev.vibeafrika.pcm.consent.application.dto;

import dev.vibeafrika.pcm.consent.domain.model.Consent;

import java.util.UUID;

/**
 * Response DTO for consent operations.
 * No framework annotations - pure data carrier.
 */
public record ConsentResponse(
    UUID id,
    UUID profileId,
    String tenantId,
    String purpose,
    String scope,
    String status,
    String createdAt,
    String updatedAt,
    Long version
) {
    public static ConsentResponse from(Consent consent) {
        return new ConsentResponse(
            consent.getId().getValue(),
            consent.getProfileId().getValue(),
            consent.getTenantId().getValue(),
            consent.getPurpose().getValue(),
            consent.getScope().getValue(),
            consent.getStatus().name(),
            consent.getCreatedAt().toString(),
            consent.getUpdatedAt().toString(),
            consent.getVersion()
        );
    }
}
