package dev.vibeafrika.pcm.segment.infrastructure.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * Spring configuration for Segment context infrastructure.
 * Enables JPA repositories and component scanning.
 */
@Configuration
@EnableJpaRepositories(basePackages = "dev.vibeafrika.pcm.segment.infrastructure.persistence.repository")
@EntityScan(basePackages = "dev.vibeafrika.pcm.segment.infrastructure.persistence.entity")
@ComponentScan(basePackages = {
    "dev.vibeafrika.pcm.segment.infrastructure.persistence",
    "dev.vibeafrika.pcm.segment.infrastructure.event"
})
public class SpringSegmentConfiguration {
}
