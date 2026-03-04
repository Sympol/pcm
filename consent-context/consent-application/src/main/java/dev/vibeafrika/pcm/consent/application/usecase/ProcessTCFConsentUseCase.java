package dev.vibeafrika.pcm.consent.application.usecase;

import dev.vibeafrika.pcm.consent.application.dto.ConsentResponse;
import dev.vibeafrika.pcm.consent.application.dto.TCFConsentRequest;
import dev.vibeafrika.pcm.consent.domain.model.*;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;

/**
 * Use case for processing IAB TCF consent.
 * No framework annotations - pure business logic.
 */
public class ProcessTCFConsentUseCase {
    private final ConsentRepository consentRepository;

    public ProcessTCFConsentUseCase(ConsentRepository consentRepository) {
        this.consentRepository = consentRepository;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public ConsentResponse execute(TCFConsentRequest request) {
        // Validate TCF data
        TCString tcString = TCString.of(request.tcString());
        VendorId vendorId = request.vendorId() != null ? VendorId.of(request.vendorId()) : null;
        PurposeId purposeId = request.purposeId() != null ? PurposeId.of(request.purposeId()) : null;

        // Create consent with TCF purpose
        ProfileId profileId = ProfileId.of(request.profileId());
        TenantId tenantId = TenantId.of(request.tenantId());
        ConsentPurpose purpose = ConsentPurpose.of("TCF_" + (purposeId != null ? purposeId.getValue() : "GENERAL"));
        ConsentScope scope = ConsentScope.of("TCF_VENDOR_" + (vendorId != null ? vendorId.getValue() : "ALL"));

        Consent consent = Consent.create(profileId, tenantId, purpose, scope);

        // Persist
        Consent savedConsent = consentRepository.save(consent);

        return ConsentResponse.from(savedConsent);
    }
}
