package dev.vibeafrika.pcm.segment.infrastructure.config;

import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration marker for Segment infrastructure module.
 * Use cases are configured in pcm-infrastructure-spring's SegmentUseCaseConfiguration
 * to avoid duplicate bean definitions in the unified Spring Boot application.
 */
@Configuration("segmentInfrastructureConfiguration")
public class SegmentUseCaseConfiguration {
    // Use cases are configured in pcm-infrastructure-spring's SegmentUseCaseConfiguration
}
