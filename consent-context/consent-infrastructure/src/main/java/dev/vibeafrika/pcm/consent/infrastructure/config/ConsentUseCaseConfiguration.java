package dev.vibeafrika.pcm.consent.infrastructure.config;

import dev.vibeafrika.pcm.consent.application.port.EventPublisher;
import dev.vibeafrika.pcm.consent.application.usecase.GrantConsentUseCase;
import dev.vibeafrika.pcm.consent.application.usecase.RevokeConsentUseCase;
import dev.vibeafrika.pcm.consent.application.usecase.RevokeConsentsForProfileUseCase;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for Consent use cases.
 * Wires use cases with their dependencies using constructor injection.
 */
@Configuration
public class ConsentUseCaseConfiguration {

    /**
     * Configure GrantConsentUseCase bean.
     * Wires the consent repository and event publisher.
     */
    @Bean
    public GrantConsentUseCase grantConsentUseCase(
            ConsentRepository consentRepository,
            EventPublisher eventPublisher) {
        return new GrantConsentUseCase(consentRepository, eventPublisher);
    }

    /**
     * Configure RevokeConsentUseCase bean.
     * Wires the consent repository and event publisher.
     */
    @Bean
    public RevokeConsentUseCase revokeConsentUseCase(
            ConsentRepository consentRepository,
            EventPublisher eventPublisher) {
        return new RevokeConsentUseCase(consentRepository, eventPublisher);
    }

    /**
     * Configure RevokeConsentsForProfileUseCase bean.
     * Wires the consent repository and event publisher.
     * Used for GDPR compliance when a profile is deleted.
     */
    @Bean
    public RevokeConsentsForProfileUseCase revokeConsentsForProfileUseCase(
            ConsentRepository consentRepository,
            EventPublisher eventPublisher) {
        return new RevokeConsentsForProfileUseCase(consentRepository, eventPublisher);
    }
}
