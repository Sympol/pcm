package dev.vibeafrika.pcm.profile.application.usecase;

import dev.vibeafrika.pcm.profile.application.dto.ProfileDataExportResponse;
import dev.vibeafrika.pcm.profile.application.port.ConsentProvider;
import dev.vibeafrika.pcm.profile.application.port.PreferenceProvider;
import dev.vibeafrika.pcm.profile.domain.exception.ProfileDeletedException;
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
    private final ConsentProvider consentProvider;
    private final PreferenceProvider preferenceProvider;

    public ExportProfileDataUseCase(
            ProfileRepository profileRepository,
            ConsentProvider consentProvider,
            PreferenceProvider preferenceProvider) {
        this.profileRepository = profileRepository;
        this.consentProvider = consentProvider;
        this.preferenceProvider = preferenceProvider;
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

        if (profile.isDeleted()) {
            throw new ProfileDeletedException("Cannot export data for an erased profile");
        }

        // 2. Fetch all consents for this profile via port
        var consents = consentProvider.getConsentsForProfile(profileId.getValue());

        // 3. Fetch preferences for this profile via port
        var preferences = preferenceProvider.getPreferencesForProfile(profileId.getValue(), tenantId.getValue());

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