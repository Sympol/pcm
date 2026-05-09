package dev.vibeafrika.pcm.profile.infrastructure.external;

import dev.vibeafrika.pcm.preference.domain.repository.PreferenceRepository;
import dev.vibeafrika.pcm.profile.application.dto.ProfileDataExportResponse;
import dev.vibeafrika.pcm.profile.application.port.PreferenceProvider;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

/**
 * Adapter that bridges the Profile context with the Preference context.
 */
@Component
public class ExternalPreferenceAdapter implements PreferenceProvider {
    private final PreferenceRepository preferenceRepository;

    public ExternalPreferenceAdapter(PreferenceRepository preferenceRepository) {
        this.preferenceRepository = preferenceRepository;
    }

    @Override
    public List<ProfileDataExportResponse.PreferenceExportEntry> getPreferencesForProfile(UUID profileId, String tenantId) {
        return preferenceRepository.findByProfileIdAndTenant(
                        dev.vibeafrika.pcm.preference.domain.model.ProfileId.of(profileId),
                        dev.vibeafrika.pcm.preference.domain.model.TenantId.of(tenantId))
                .map(pref -> new ProfileDataExportResponse.PreferenceExportEntry(
                        pref.getId().getValue(),
                        pref.getSettings(),
                        pref.getLastUpdated().toString(),
                        pref.getLastUpdated().toString()
                ))
                .stream()
                .toList();
    }
}
