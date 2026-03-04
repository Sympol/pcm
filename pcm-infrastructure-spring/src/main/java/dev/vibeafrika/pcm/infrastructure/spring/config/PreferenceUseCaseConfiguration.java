package dev.vibeafrika.pcm.infrastructure.spring.config;

import dev.vibeafrika.pcm.preference.application.port.EventPublisher;
import dev.vibeafrika.pcm.preference.application.usecase.*;
import dev.vibeafrika.pcm.preference.domain.repository.PreferenceRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for Preference use cases.
 * Wires use cases with their dependencies using constructor injection.
 * Part of the unified Spring Boot infrastructure.
 */
@Configuration
public class PreferenceUseCaseConfiguration {

    /**
     * Configure CreatePreferenceUseCase bean.
     */
    @Bean
    public CreatePreferenceUseCase createPreferenceUseCase(
            PreferenceRepository preferenceRepository,
            EventPublisher eventPublisher) {
        return new CreatePreferenceUseCase(preferenceRepository, eventPublisher);
    }

    /**
     * Configure UpdatePreferenceUseCase bean.
     */
    @Bean
    public UpdatePreferenceUseCase updatePreferenceUseCase(
            PreferenceRepository preferenceRepository,
            EventPublisher eventPublisher) {
        return new UpdatePreferenceUseCase(preferenceRepository, eventPublisher);
    }

    /**
     * Configure GetPreferenceUseCase bean.
     */
    @Bean
    public GetPreferenceUseCase getPreferenceUseCase(
            PreferenceRepository preferenceRepository) {
        return new GetPreferenceUseCase(preferenceRepository);
    }

    /**
     * Configure DeletePreferenceUseCase bean.
     */
    @Bean
    public DeletePreferenceUseCase deletePreferenceUseCase(
            PreferenceRepository preferenceRepository,
            EventPublisher eventPublisher) {
        return new DeletePreferenceUseCase(preferenceRepository, eventPublisher);
    }
}
