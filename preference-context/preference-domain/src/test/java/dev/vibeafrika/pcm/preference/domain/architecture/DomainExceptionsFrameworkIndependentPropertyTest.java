package dev.vibeafrika.pcm.preference.domain.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Property-based test for domain exceptions being framework-independent.
 * 
 * Feature: framework-agnostic-domain, Property 15: Domain Exceptions Are Framework-Independent
 * 
 * This test verifies that:
 * 1. Domain exceptions do NOT extend framework-specific exception types
 * 2. Domain exceptions only extend RuntimeException or other domain exceptions
 * 3. Domain exceptions have NO framework annotations
 */
class DomainExceptionsFrameworkIndependentPropertyTest {

    private static JavaClasses domainClasses;

    @BeforeAll
    static void importClasses() {
        domainClasses = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.vibeafrika.pcm.preference.domain");
    }

    @Test
    void domainExceptionsShouldNotExtendSpringExceptions() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain.exception..")
            .should().beAssignableTo("org.springframework.core.NestedRuntimeException")
            .orShould().beAssignableTo("org.springframework.web.server.ResponseStatusException")
            .because("Domain exceptions must not extend Spring exception types");

        rule.check(domainClasses);
    }

    @Test
    void domainExceptionsShouldNotExtendJakartaExceptions() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain.exception..")
            .should().beAssignableTo("jakarta.ws.rs.WebApplicationException")
            .orShould().beAssignableTo("javax.ws.rs.WebApplicationException")
            .because("Domain exceptions must not extend JAX-RS exception types");

        rule.check(domainClasses);
    }

    @Test
    void domainExceptionsShouldExtendRuntimeExceptionOrDomainException() {
        ArchRule rule = classes()
            .that().resideInAPackage("..domain.exception..")
            .and().haveSimpleNameEndingWith("Exception")
            .should().beAssignableTo(RuntimeException.class)
            .because("Domain exceptions should extend RuntimeException or other domain exceptions");

        rule.check(domainClasses);
    }

    @Test
    void domainExceptionsShouldNotHaveFrameworkAnnotations() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain.exception..")
            .should().beAnnotatedWith("org.springframework.web.bind.annotation.ResponseStatus")
            .orShould().beAnnotatedWith("jakarta.ws.rs.ext.Provider")
            .orShould().beAnnotatedWith("org.springframework.stereotype.Component")
            .because("Domain exceptions must not have framework annotations");

        rule.check(domainClasses);
    }

    @Test
    void domainExceptionsShouldOnlyDependOnDomainTypes() {
        ArchRule rule = classes()
            .that().resideInAPackage("..domain.exception..")
            .should().onlyDependOnClassesThat().resideInAnyPackage(
                "java..",
                "..domain.."
            )
            .because("Domain exceptions should only depend on domain types");

        rule.check(domainClasses);
    }
}
