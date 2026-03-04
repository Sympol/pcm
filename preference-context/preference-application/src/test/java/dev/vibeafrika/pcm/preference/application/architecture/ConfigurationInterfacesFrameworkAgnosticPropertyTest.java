package dev.vibeafrika.pcm.preference.application.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Property-based test for configuration interfaces being framework-agnostic.
 * 
 * **Validates: Requirements 20.2**
 * 
 * Feature: framework-agnostic-domain, Property 18: Configuration Interfaces Are Framework-Agnostic
 * 
 * This test verifies that:
 * 1. Configuration interfaces do NOT use framework-specific annotations
 * 2. Configuration interfaces are pure Java interfaces
 * 3. Configuration interfaces only depend on domain types
 */
class ConfigurationInterfacesFrameworkAgnosticPropertyTest {

    private static JavaClasses applicationClasses;

    @BeforeAll
    static void importClasses() {
        applicationClasses = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.vibeafrika.pcm.preference.application");
    }

    @Test
    void configurationInterfacesShouldNotHaveSpringAnnotations() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application.config..")
            .and().haveSimpleNameEndingWith("Configuration")
            .should().beAnnotatedWith("org.springframework.boot.context.properties.ConfigurationProperties")
            .orShould().beAnnotatedWith("org.springframework.context.annotation.Configuration")
            .orShould().beAnnotatedWith("org.springframework.beans.factory.annotation.Value")
            .orShould().beAnnotatedWith("org.springframework.stereotype.Component")
            .because("Configuration interfaces must not use Spring annotations (Requirement 20.2)");

        rule.check(applicationClasses);
    }

    @Test
    void configurationInterfacesShouldNotHaveQuarkusAnnotations() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application.config..")
            .and().haveSimpleNameEndingWith("Configuration")
            .should().beAnnotatedWith("io.smallrye.config.ConfigMapping")
            .orShould().beAnnotatedWith("io.quarkus.arc.config.ConfigProperties")
            .orShould().beAnnotatedWith("jakarta.enterprise.context.ApplicationScoped")
            .because("Configuration interfaces must not use Quarkus annotations (Requirement 20.2)");

        rule.check(applicationClasses);
    }

    @Test
    void configurationInterfacesShouldBeInterfaces() {
        ArchRule rule = classes()
            .that().resideInAPackage("..application.config..")
            .and().haveSimpleNameEndingWith("Configuration")
            .should().beInterfaces()
            .because("Configuration contracts should be defined as interfaces (Requirement 20.2)");

        rule.check(applicationClasses);
    }

    @Test
    void configurationInterfacesShouldOnlyDependOnDomainTypes() {
        ArchRule rule = classes()
            .that().resideInAPackage("..application.config..")
            .and().haveSimpleNameEndingWith("Configuration")
            .should().onlyDependOnClassesThat().resideInAnyPackage(
                "java..",
                "..domain.."
            )
            .because("Configuration interfaces should only depend on domain types (Requirement 20.2)");

        rule.check(applicationClasses);
    }
}
