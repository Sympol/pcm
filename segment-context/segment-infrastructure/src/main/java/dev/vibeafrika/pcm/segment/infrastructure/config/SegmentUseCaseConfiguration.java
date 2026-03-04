package dev.vibeafrika.pcm.segment.infrastructure.config;

import dev.vibeafrika.pcm.segment.application.usecase.EvaluateSegmentForPreferenceUseCase;
import dev.vibeafrika.pcm.segment.application.usecase.EvaluateSegmentForProfileUseCase;
import dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for Segment use cases.
 * Wires use cases with their dependencies using constructor injection.
 */
@Configuration
public class SegmentUseCaseConfiguration {

    /**
     * Configure EvaluateSegmentForPreferenceUseCase bean.
     * This use case is triggered by inter-context events from Preference context.
     */
    @Bean
    public EvaluateSegmentForPreferenceUseCase evaluateSegmentForPreferenceUseCase(
            SegmentRepository segmentRepository) {
        return new EvaluateSegmentForPreferenceUseCase(segmentRepository);
    }

    /**
     * Configure EvaluateSegmentForProfileUseCase bean.
     * This use case is triggered by inter-context events from Profile context.
     */
    @Bean
    public EvaluateSegmentForProfileUseCase evaluateSegmentForProfileUseCase(
            SegmentRepository segmentRepository) {
        return new EvaluateSegmentForProfileUseCase(segmentRepository);
    }
}
