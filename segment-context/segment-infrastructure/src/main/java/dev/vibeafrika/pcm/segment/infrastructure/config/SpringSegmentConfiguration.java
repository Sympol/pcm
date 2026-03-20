package dev.vibeafrika.pcm.segment.infrastructure.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for Segment context infrastructure.
 * Component scanning for segment infrastructure beans.
 * JPA repositories and entity scanning are configured in PcmApplication.
 */
@Configuration
@ComponentScan(basePackages = {
    "dev.vibeafrika.pcm.segment.infrastructure.persistence",
    "dev.vibeafrika.pcm.segment.infrastructure.event"
})
public class SpringSegmentConfiguration {
}
