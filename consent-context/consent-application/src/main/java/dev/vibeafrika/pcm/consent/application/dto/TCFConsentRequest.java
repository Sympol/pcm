package dev.vibeafrika.pcm.consent.application.dto;

import java.util.UUID;

/**
 * Request DTO for IAB TCF consent processing.
 * No framework annotations - pure data carrier.
 */
public record TCFConsentRequest(
    UUID profileId,
    String tenantId,
    String tcString,
    Integer vendorId,
    Integer purposeId
) {
    public TCFConsentRequest {
        if (profileId == null) {
            throw new IllegalArgumentException("Profile ID is required");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("Tenant ID is required");
        }
        if (tcString == null || tcString.isBlank()) {
            throw new IllegalArgumentException("TC String is required");
        }
    }
}
