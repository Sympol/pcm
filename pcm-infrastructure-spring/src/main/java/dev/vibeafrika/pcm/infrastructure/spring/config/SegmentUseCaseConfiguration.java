package dev.vibeafrika.pcm.infrastructure.spring.config;

import dev.vibeafrika.pcm.segment.application.usecase.*;
import dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for Segment context use cases.
 * Wires use cases with their dependencies using constructor injection.
 */
@Configuration
public class SegmentUseCaseConfiguration {

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
            SegmentRepository segmentRepository) {
        return new EvaluateSegmentForPreferenceUseCase(segmentRepository);
    }

    @Bean
    public EvaluateSegmentForProfileUseCase evaluateSegmentForProfileUseCase(
            SegmentRepository segmentRepository) {
        return new EvaluateSegmentForProfileUseCase(segmentRepository);
    }
}
