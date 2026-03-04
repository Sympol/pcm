package dev.vibeafrika.pcm.consent.application.dto;

import java.util.UUID;

/**
 * Request DTO for revoking consent.
 * No framework annotations - pure data carrier.
 */
public record RevokeConsentRequest(
    UUID consentId,
    String tenantId
) {
    public RevokeConsentRequest {
        if (consentId == null) {
            throw new IllegalArgumentException("Consent ID is required");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
    }
}
