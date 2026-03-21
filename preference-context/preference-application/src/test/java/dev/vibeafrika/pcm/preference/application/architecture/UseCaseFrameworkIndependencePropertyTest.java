package dev.vibeafrika.pcm.preference.application.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

/**
 * Property-based tests for use case framework independence.
 *
 * Feature: framework-agnostic-domain
 *
 * Property 6: Application Layer Framework Independence
 *   - The application layer must have zero Spring, JPA, or web framework dependencies
 *
 * Property 7: Use Cases Depend Only on Domain Contracts
 *   - Use cases must only depend on domain interfaces, domain types, and application DTOs
 *
 * Property 9: Use Cases Are Transaction-Annotation-Free
 *   - Use cases must not carry @Transactional or any framework transaction annotations
 */
class UseCaseFrameworkIndependencePropertyTest {

    private static JavaClasses applicationClasses;

    @BeforeAll
    static void importClasses() {
        applicationClasses = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.vibeafrika.pcm.preference.application");
    }

    // -------------------------------------------------------------------------
    // Property 6: Application Layer Framework Independence
    // -------------------------------------------------------------------------

    @Test
    void applicationLayerShouldNotDependOnSpring() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application..")
            .should().dependOnClassesThat().resideInAPackage("org.springframework..")
            .because("Application layer must have zero Spring dependencies");

        rule.check(applicationClasses);
    }

    @Test
    void applicationLayerShouldNotDependOnJpa() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "jakarta.persistence..",
                "javax.persistence..",
                "org.hibernate.."
            )
            .because("Application layer must have zero JPA/Hibernate dependencies");

        rule.check(applicationClasses);
    }

    @Test
    void applicationLayerShouldNotDependOnWebFrameworks() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "jakarta.servlet..",
                "javax.servlet..",
                "jakarta.ws.rs..",
                "io.quarkus.."
            )
            .because("Application layer must have zero web framework dependencies");

        rule.check(applicationClasses);
    }

    // -------------------------------------------------------------------------
    // Property 7: Use Cases Depend Only on Domain Contracts
    // -------------------------------------------------------------------------

    @Test
    void useCasesShouldOnlyDependOnAllowedPackages() {
        ArchRule rule = classes()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should().onlyDependOnClassesThat().resideInAnyPackage(
                "java..",
                "..domain..",
                "..application.dto..",
                "..application.config..",
                "..application.port..",
                "..application.event.."
            )
            .because("Use cases must only depend on domain contracts and application DTOs");

        rule.check(applicationClasses);
    }

    @Test
    void useCasesShouldNotDependOnInfrastructureClasses() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application.usecase..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "..infrastructure..",
                "..persistence..",
                "..web..",
                "..controller.."
            )
            .because("Use cases must not depend on infrastructure classes");

        rule.check(applicationClasses);
    }

    @Test
    void useCasesShouldNotHaveSpringStereotypeAnnotations() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should().beAnnotatedWith("org.springframework.stereotype.Service")
            .orShould().beAnnotatedWith("org.springframework.stereotype.Component")
            .orShould().beAnnotatedWith("org.springframework.stereotype.Repository")
            .because("Use cases must not carry Spring stereotype annotations");

        rule.check(applicationClasses);
    }

    // -------------------------------------------------------------------------
    // Property 9: Use Cases Are Transaction-Annotation-Free
    // -------------------------------------------------------------------------

    @Test
    void useCaseClassesShouldNotHaveSpringTransactionalAnnotation() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should().beAnnotatedWith("org.springframework.transaction.annotation.Transactional")
            .because("Use cases must not use @Transactional - transaction management belongs in infrastructure");

        rule.check(applicationClasses);
    }

    @Test
    void useCaseMethodsShouldNotHaveSpringTransactionalAnnotation() {
        ArchRule rule = noMethods()
            .that().areDeclaredInClassesThat().resideInAPackage("..application.usecase..")
            .and().areDeclaredInClassesThat().haveSimpleNameEndingWith("UseCase")
            .should().beAnnotatedWith("org.springframework.transaction.annotation.Transactional")
            .because("Use case methods must not use @Transactional");

        rule.check(applicationClasses);
    }

    @Test
    void useCaseClassesShouldNotHaveJakartaTransactionalAnnotation() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should().beAnnotatedWith("jakarta.transaction.Transactional")
            .because("Use cases must not use Jakarta @Transactional at class level");

        rule.check(applicationClasses);
    }

    @Test
    void useCaseMethodsShouldNotHaveJakartaTransactionalAnnotation() {
        ArchRule rule = noMethods()
            .that().areDeclaredInClassesThat().resideInAPackage("..application.usecase..")
            .and().areDeclaredInClassesThat().haveSimpleNameEndingWith("UseCase")
            .should().beAnnotatedWith("jakarta.transaction.Transactional")
            .because("Use case methods must not use Jakarta @Transactional");

        rule.check(applicationClasses);
    }
}
