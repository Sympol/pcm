package dev.vibeafrika.pcm.consent.application.dto;

import java.util.UUID;

/**
 * Request DTO for granting consent.
 * No framework annotations - pure data carrier.
 */
public record GrantConsentRequest(
    UUID profileId,
    String tenantId,
    String purpose,
    String scope
) {
    public GrantConsentRequest {
        if (profileId == null) {
            throw new IllegalArgumentException("Profile ID is required");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
        if (purpose == null || purpose.isBlank()) {
            throw new IllegalArgumentException("Purpose is required");
        }
        if (scope == null || scope.isBlank()) {
            throw new IllegalArgumentException("Scope is required");
        }
    }
}
