package dev.vibeafrika.pcm.preference.application.usecase;

import dev.vibeafrika.pcm.preference.application.dto.GetPreferenceRequest;
import dev.vibeafrika.pcm.preference.application.dto.PreferenceResponse;
import dev.vibeafrika.pcm.preference.domain.exception.PreferenceNotFoundException;
import dev.vibeafrika.pcm.preference.domain.model.Preference;
import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import dev.vibeafrika.pcm.preference.domain.repository.PreferenceRepository;

/**
 * Use case for retrieving a preference.
 */
public class GetPreferenceUseCase {
    private final PreferenceRepository preferenceRepository;

    // Constructor injection - no framework annotations
    public GetPreferenceUseCase(PreferenceRepository preferenceRepository) {
        this.preferenceRepository = preferenceRepository;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public PreferenceResponse execute(GetPreferenceRequest request) {
        // Load preference by ID
        PreferenceId preferenceId = PreferenceId.of(request.preferenceId());
        
        Preference preference = preferenceRepository.findById(preferenceId)
            .orElseThrow(() -> new PreferenceNotFoundException(preferenceId));

        // Return DTO
        return PreferenceResponse.from(preference);
    }
}
