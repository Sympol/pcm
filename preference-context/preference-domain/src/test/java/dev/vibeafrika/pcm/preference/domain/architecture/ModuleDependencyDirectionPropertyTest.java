package dev.vibeafrika.pcm.preference.domain.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Property-based test for module dependency direction.
 * 
 * **Validates: Requirements 9.2, 9.3, 9.4**
 * 
 * Feature: framework-agnostic-domain, Property 10: Module Dependency Direction
 * 
 * This test verifies that:
 * 1. Domain module depends on NOTHING (except Java stdlib and pure-assert)
 * 2. Application module depends ONLY on domain module
 * 3. Infrastructure module depends on domain and application modules
 * 4. No circular dependencies between layers
 */
class ModuleDependencyDirectionPropertyTest {

    private static JavaClasses allClasses;

    @BeforeAll
    static void importClasses() {
        allClasses = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.vibeafrika.pcm.preference");
    }

    @Test
    void domainShouldNotDependOnApplication() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideInAPackage("..application..")
            .because("Domain module must not depend on application module (Requirement 9.3)");

        rule.check(allClasses);
    }

    @Test
    void domainShouldNotDependOnInfrastructure() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideInAPackage("..infrastructure..")
            .because("Domain module must not depend on infrastructure module (Requirement 9.3)");

        rule.check(allClasses);
    }

    @Test
    void applicationShouldNotDependOnInfrastructure() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application..")
            .should().dependOnClassesThat().resideInAPackage("..infrastructure..")
            .because("Application module must not depend on infrastructure module (Requirement 9.4)")
            .allowEmptyShould(true);  // Allow empty if application classes not in classpath

        rule.check(allClasses);
    }

    @Test
    void domainShouldOnlyDependOnDomainAndStandardLibrary() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideOutsideOfPackages(
                "java..",
                "dev.vibeafrika.pcm.preference.domain..",
                "dev.vibeafrika.pcm.domain..",  // Shared domain concepts
                "io.github.sympol.pure.."  // pure-assert
            )
            .because("Domain module must have zero external dependencies (Requirement 9.2)");

        rule.check(allClasses);
    }

    @Test
    void applicationShouldOnlyDependOnDomainAndStandardLibrary() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application..")
            .should().dependOnClassesThat().resideOutsideOfPackages(
                "java..",
                "dev.vibeafrika.pcm.preference.domain..",
                "dev.vibeafrika.pcm.preference.application..",
                "dev.vibeafrika.pcm.domain.."  // Shared domain concepts
            )
            .because("Application module must only depend on domain module (Requirement 9.4)")
            .allowEmptyShould(true);  // Allow empty if application classes not in classpath

        rule.check(allClasses);
    }
}
