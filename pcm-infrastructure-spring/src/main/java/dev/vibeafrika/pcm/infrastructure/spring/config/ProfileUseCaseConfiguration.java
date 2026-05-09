package dev.vibeafrika.pcm.infrastructure.spring.config;

import dev.vibeafrika.pcm.profile.application.port.ConsentProvider;
import dev.vibeafrika.pcm.profile.application.port.EventPublisher;
import dev.vibeafrika.pcm.profile.application.port.PreferenceProvider;
import dev.vibeafrika.pcm.profile.application.usecase.*;
import dev.vibeafrika.pcm.profile.domain.repository.ProfileRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for Profile use cases.
 */
@Configuration
public class ProfileUseCaseConfiguration {

    @Bean
    public CreateProfileUseCase createProfileUseCase(
            ProfileRepository profileRepository,
            EventPublisher eventPublisher) {
        return new CreateProfileUseCase(profileRepository, eventPublisher);
    }

    @Bean
    public UpdateProfileUseCase updateProfileUseCase(
            ProfileRepository profileRepository,
            EventPublisher eventPublisher) {
        return new UpdateProfileUseCase(profileRepository, eventPublisher);
    }

    @Bean
    public GetProfileUseCase getProfileUseCase(ProfileRepository profileRepository) {
        return new GetProfileUseCase(profileRepository);
    }

    @Bean
    public EraseProfileUseCase eraseProfileUseCase(
            ProfileRepository profileRepository,
            EventPublisher eventPublisher) {
        return new EraseProfileUseCase(profileRepository, eventPublisher);
    }

    @Bean
    public ExportProfileDataUseCase exportProfileDataUseCase(
            ProfileRepository profileRepository,
            ConsentProvider consentProvider,
            PreferenceProvider preferenceProvider) {
        return new ExportProfileDataUseCase(profileRepository, consentProvider, preferenceProvider);
    }
}
