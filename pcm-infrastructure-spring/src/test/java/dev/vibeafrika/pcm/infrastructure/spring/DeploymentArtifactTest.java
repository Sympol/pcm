package dev.vibeafrika.pcm.infrastructure.spring;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies deployment artifact correctness for the Spring Boot adapter.
 *
 */
@DisplayName("Deployment Artifact Verification")
class DeploymentArtifactTest {

    @Test
    @DisplayName("Spring Boot main class is present on the classpath")
    void springBootMainClassIsPresent() {
        assertDoesNotThrow(
            () -> Class.forName("dev.vibeafrika.pcm.infrastructure.spring.PcmApplication"),
            "Spring Boot main class PcmApplication must be present on the classpath"
        );
    }

    @Test
    @DisplayName("No Quarkus classes are present on the classpath")
    void quarkusClassesAreAbsent() {
        assertThrows(
            ClassNotFoundException.class,
            () -> Class.forName("io.quarkus.runtime.Quarkus"),
            "Quarkus runtime class must NOT be present in the Spring Boot artifact"
        );
    }

    @Test
    @DisplayName("Preference domain module classes are accessible")
    void preferenceDomainClassesAreAccessible() {
        assertDoesNotThrow(
            () -> Class.forName("dev.vibeafrika.pcm.preference.domain.model.Preference"),
            "Preference domain class must be accessible from the Spring Boot artifact"
        );
    }

    @Test
    @DisplayName("Preference application module classes are accessible")
    void preferenceApplicationClassesAreAccessible() {
        assertDoesNotThrow(
            () -> Class.forName("dev.vibeafrika.pcm.preference.application.usecase.CreatePreferenceUseCase"),
            "CreatePreferenceUseCase application class must be accessible from the Spring Boot artifact"
        );
    }
}
