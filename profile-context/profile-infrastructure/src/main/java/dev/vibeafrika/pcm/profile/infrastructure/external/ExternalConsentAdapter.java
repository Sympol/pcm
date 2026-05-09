package dev.vibeafrika.pcm.profile.infrastructure.external;

import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;
import dev.vibeafrika.pcm.profile.application.dto.ProfileDataExportResponse;
import dev.vibeafrika.pcm.profile.application.port.ConsentProvider;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

/**
 * Adapter that bridges the Profile context with the Consent context.
 */
@Component
public class ExternalConsentAdapter implements ConsentProvider {
    private final ConsentRepository consentRepository;

    public ExternalConsentAdapter(ConsentRepository consentRepository) {
        this.consentRepository = consentRepository;
    }

    @Override
    public List<ProfileDataExportResponse.ConsentExportEntry> getConsentsForProfile(UUID profileId) {
        return consentRepository.findByProfile(dev.vibeafrika.pcm.consent.domain.model.ProfileId.of(profileId))
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
    }
}
