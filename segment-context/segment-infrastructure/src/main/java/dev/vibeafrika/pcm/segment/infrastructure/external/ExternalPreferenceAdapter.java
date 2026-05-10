package dev.vibeafrika.pcm.segment.infrastructure.external;

import dev.vibeafrika.pcm.preference.domain.repository.PreferenceRepository;
import dev.vibeafrika.pcm.segment.application.port.PreferenceProvider;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.UUID;

/**
 * Adapter that provides preference data from the preference context to the segment context.
 */
@Component("segmentExternalPreferenceAdapter")
public class ExternalPreferenceAdapter implements PreferenceProvider {

    private final PreferenceRepository preferenceRepository;

    public ExternalPreferenceAdapter(PreferenceRepository preferenceRepository) {
        this.preferenceRepository = preferenceRepository;
    }

    @Override
    public Map<String, Object> getPreferences(UUID profileId, String tenantId) {
        return preferenceRepository.findByProfileIdAndTenant(
                dev.vibeafrika.pcm.preference.domain.model.ProfileId.of(profileId),
                dev.vibeafrika.pcm.preference.domain.model.TenantId.of(tenantId)
        )
        .map(pref -> {
            Map<String, Object> settings = new java.util.HashMap<>();
            pref.getSettings().forEach(settings::put);
            return settings;
        })
        .orElse(Map.of());
    }
}
