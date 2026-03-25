package dev.vibeafrika.pcm.profile.infrastructure.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration for Profile infrastructure module.
 * Enables component scanning for Profile infrastructure components
 * (repository adapters, event publishers, etc.).
 *
 * <p>Use case beans are configured in pcm-infrastructure-spring's
 * ProfileUseCaseConfiguration to avoid duplicate bean definitions
 * in the unified Spring Boot application.
 */
@Configuration
@ComponentScan(basePackages = "dev.vibeafrika.pcm.profile.infrastructure")
public class ProfileApplicationConfig {
    // Use case beans are wired in pcm-infrastructure-spring's ProfileUseCaseConfiguration.
    // This class enables component scanning for infrastructure adapters
    // (ProfileRepositoryAdapter, SpringProfileConfiguration, etc.)
    // so they are discovered and registered as Spring beans.
}
