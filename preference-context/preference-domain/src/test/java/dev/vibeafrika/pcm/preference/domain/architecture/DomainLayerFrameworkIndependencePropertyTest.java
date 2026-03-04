package dev.vibeafrika.pcm.preference.domain.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

/**
 * Property-based test for domain layer framework independence.
 * 
 * **Validates: Requirements 1.1, 1.2, 1.3, 1.4**
 * 
 * Feature: framework-agnostic-domain, Property 1: Domain Layer Framework Independence
 * 
 * This test verifies that:
 * 1. Domain layer has ZERO dependencies on Spring Framework
 * 2. Domain layer has ZERO dependencies on JPA/Hibernate
 * 3. Domain layer has ZERO dependencies on any web framework
 * 4. Domain entities use only standard Java features
 */
class DomainLayerFrameworkIndependencePropertyTest {

    private static JavaClasses domainClasses;

    @BeforeAll
    static void importClasses() {
        domainClasses = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.vibeafrika.pcm.preference.domain");
    }

    @Test
    void domainLayerShouldNotDependOnSpringFramework() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "org.springframework..",
                "org.springframework.boot..",
                "org.springframework.context..",
                "org.springframework.beans..",
                "org.springframework.data..",
                "org.springframework.web..",
                "org.springframework.stereotype..",
                "org.springframework.transaction.."
            )
            .because("Domain layer must be framework-independent (Requirement 1.1)");

        rule.check(domainClasses);
    }

    @Test
    void domainLayerShouldNotDependOnJPA() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "jakarta.persistence..",
                "javax.persistence..",
                "org.hibernate..",
                "org.hibernate.annotations.."
            )
            .because("Domain layer must not depend on JPA/Hibernate (Requirement 1.2)");

        rule.check(domainClasses);
    }

    @Test
    void domainLayerShouldNotDependOnWebFrameworks() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "jakarta.ws.rs..",
                "javax.ws.rs..",
                "jakarta.servlet..",
                "javax.servlet..",
                "org.springframework.web..",
                "io.quarkus..",
                "io.micronaut.."
            )
            .because("Domain layer must not depend on web frameworks (Requirement 1.3)");

        rule.check(domainClasses);
    }

    @Test
    void domainLayerShouldNotDependOnValidationFrameworks() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "jakarta.validation..",
                "javax.validation..",
                "org.hibernate.validator.."
            )
            .because("Domain layer uses pure-assert for validation, not framework validation");

        rule.check(domainClasses);
    }

    @Test
    void domainLayerShouldOnlyDependOnJavaStandardLibraryAndPureAssert() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideOutsideOfPackages(
                "java..",
                "dev.vibeafrika.pcm..",
                "io.github.sympol.pure.."  // pure-assert is the ONLY allowed external dependency
            )
            .because("Domain layer must only depend on Java stdlib and pure-assert (Requirement 1.4)");

        rule.check(domainClasses);
    }
}
