package dev.vibeafrika.pcm.profile.application.usecase;

import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;
import dev.vibeafrika.pcm.preference.domain.repository.PreferenceRepository;
import dev.vibeafrika.pcm.profile.application.dto.ProfileDataExportResponse;
import dev.vibeafrika.pcm.profile.domain.exception.ProfileNotFoundException;
import dev.vibeafrika.pcm.profile.domain.model.Profile;
import dev.vibeafrika.pcm.profile.domain.model.ProfileId;
import dev.vibeafrika.pcm.profile.domain.model.TenantId;
import dev.vibeafrika.pcm.profile.domain.repository.ProfileRepository;

import java.time.Instant;
import java.util.UUID;

/**
 * Use case for exporting all personal data held by PCM for a given profile.
 *
 * <p>This use case aggregates data from all four bounded contexts:
 * Profile, Consent, Preference, and Segment (if applicable).
 *
 * <p>No framework annotations — pure business logic.
 */
public class ExportProfileDataUseCase {
    private final ProfileRepository profileRepository;
    private final ConsentRepository consentRepository;
    private final PreferenceRepository preferenceRepository;

    public ExportProfileDataUseCase(
            ProfileRepository profileRepository,
            ConsentRepository consentRepository,
            PreferenceRepository preferenceRepository) {
        this.profileRepository = profileRepository;
        this.consentRepository = consentRepository;
        this.preferenceRepository = preferenceRepository;
    }

    /**
     * Execute the data portability export.
     *
     * @param profileIdStr the profile ID as string
     * @param tenantIdStr  the tenant ID as string (for tenant isolation)
     * @return a structured export containing all personal data
     * @throws ProfileNotFoundException if the profile does not exist
     */
    public ProfileDataExportResponse execute(String profileIdStr, String tenantIdStr) {
        ProfileId profileId = ProfileId.of(UUID.fromString(profileIdStr));
        TenantId tenantId = TenantId.of(tenantIdStr);

        // 1. Fetch profile (tenant-isolated)
        Profile profile = profileRepository.findByIdAndTenant(profileId, tenantId)
                .orElseThrow(() -> new ProfileNotFoundException(profileId));

        // 2. Fetch all consents for this profile
        var consents = consentRepository.findByProfile(dev.vibeafrika.pcm.consent.domain.model.ProfileId.of(profileId.getValue()))
                .stream()
                .map(consent -> new ProfileDataExportResponse.ConsentExportEntry(
                        consent.getId().getValue(),
                        consent.getPurpose().getValue(),
                        consent.getScope().getValue(),
                        consent.getStatus().name(),
                        consent.getCreatedAt().toString(),
                        consent.getUpdatedAt().toString(),
                        consent.getHistory().stream()
                                .map(event -> new ProfileDataExportResponse.ConsentEventEntry(
                                        event.getStatus().name(),
                                        event.getTimestamp().toString()
                                ))
                                .toList()
                ))
                .toList();

        // 3. Fetch preferences for this profile
        var preferences = preferenceRepository.findByProfileIdAndTenant(
                        dev.vibeafrika.pcm.preference.domain.model.ProfileId.of(profileId.getValue()),
                        dev.vibeafrika.pcm.preference.domain.model.TenantId.of(tenantIdStr))
                .map(pref -> new ProfileDataExportResponse.PreferenceExportEntry(
                        pref.getId().getValue(),
                        pref.getSettings(),
                        pref.getLastUpdated().toString(),
                        pref.getLastUpdated().toString()
                ))
                .stream()
                .toList();

        // 4. Build the export response
        return new ProfileDataExportResponse(
                profileId.getValue(),
                tenantId.getValue(),
                Instant.now().toString(),
                new ProfileDataExportResponse.ProfileSection(
                        profile.getHandle().getValue(),
                        profile.getAttributes(),
                        profile.getCreatedAt().toString(),
                        profile.getUpdatedAt().toString()
                ),
                consents,
                preferences
        );
    }
}
