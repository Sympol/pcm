package dev.vibeafrika.pcm.consent.infrastructure.config;

import dev.vibeafrika.pcm.consent.application.port.EventPublisher;
import dev.vibeafrika.pcm.consent.application.usecase.*;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for Consent use cases.
 * Wires use cases with their dependencies using constructor injection.
 */
@Configuration
public class ConsentUseCaseConfiguration {

    @Bean
    public GrantConsentUseCase grantConsentUseCase(
            ConsentRepository consentRepository,
            EventPublisher eventPublisher) {
        return new GrantConsentUseCase(consentRepository, eventPublisher);
    }

    @Bean
    public RevokeConsentUseCase revokeConsentUseCase(
            ConsentRepository consentRepository,
            EventPublisher eventPublisher) {
        return new RevokeConsentUseCase(consentRepository, eventPublisher);
    }

    @Bean
    public VerifyConsentUseCase verifyConsentUseCase(ConsentRepository consentRepository) {
        return new VerifyConsentUseCase(consentRepository);
    }

    @Bean
    public GetConsentHistoryUseCase getConsentHistoryUseCase(ConsentRepository consentRepository) {
        return new GetConsentHistoryUseCase(consentRepository);
    }

    @Bean
    public RevokeConsentsForProfileUseCase revokeConsentsForProfileUseCase(
            ConsentRepository consentRepository,
            EventPublisher eventPublisher) {
        return new RevokeConsentsForProfileUseCase(consentRepository, eventPublisher);
    }
}
