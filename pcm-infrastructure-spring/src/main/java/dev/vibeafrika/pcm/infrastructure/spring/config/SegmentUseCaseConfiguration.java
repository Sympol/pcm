package dev.vibeafrika.pcm.infrastructure.spring.config;

import dev.vibeafrika.pcm.segment.application.port.EventPublisher;
import dev.vibeafrika.pcm.segment.application.port.PreferenceProvider;
import dev.vibeafrika.pcm.segment.application.port.ProfileProvider;
import dev.vibeafrika.pcm.segment.application.usecase.*;
import dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository;
import dev.vibeafrika.pcm.segment.domain.service.SegmentEvaluationService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for Segment context use cases.
 */
@Configuration
public class SegmentUseCaseConfiguration {

    @Bean
    public SegmentEvaluationService segmentEvaluationService() {
        return new SegmentEvaluationService();
    }

    @Bean
    public CreateSegmentUseCase createSegmentUseCase(SegmentRepository segmentRepository) {
        return new CreateSegmentUseCase(segmentRepository);
    }

    @Bean
    public UpdateSegmentUseCase updateSegmentUseCase(SegmentRepository segmentRepository) {
        return new UpdateSegmentUseCase(segmentRepository);
    }

    @Bean
    public GetSegmentUseCase getSegmentUseCase(SegmentRepository segmentRepository) {
        return new GetSegmentUseCase(segmentRepository);
    }

    @Bean
    public DeleteSegmentUseCase deleteSegmentUseCase(SegmentRepository segmentRepository) {
        return new DeleteSegmentUseCase(segmentRepository);
    }

    @Bean
    public EvaluateSegmentUseCase evaluateSegmentUseCase(SegmentRepository segmentRepository) {
        return new EvaluateSegmentUseCase(segmentRepository);
    }

    @Bean
    public EvaluateSegmentForPreferenceUseCase evaluateSegmentForPreferenceUseCase(
            SegmentRepository segmentRepository,
            ProfileProvider profileProvider,
            PreferenceProvider preferenceProvider,
            @Qualifier("segmentSpringEventPublisher") EventPublisher eventPublisher,
            SegmentEvaluationService evaluationService) {
        return new EvaluateSegmentForPreferenceUseCase(segmentRepository, profileProvider, preferenceProvider, eventPublisher, evaluationService);
    }

    @Bean
    public EvaluateSegmentForProfileUseCase evaluateSegmentForProfileUseCase(
            SegmentRepository segmentRepository,
            ProfileProvider profileProvider,
            PreferenceProvider preferenceProvider,
            @Qualifier("segmentSpringEventPublisher") EventPublisher eventPublisher,
            SegmentEvaluationService evaluationService) {
        return new EvaluateSegmentForProfileUseCase(segmentRepository, profileProvider, preferenceProvider, eventPublisher, evaluationService);
    }
}
