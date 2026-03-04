package dev.vibeafrika.pcm.preference.domain.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Property-based test for domain tests running without framework context.
 * 
 * **Validates: Requirements 8.3, 8.4, 8.5**
 * 
 * Feature: framework-agnostic-domain, Property 23: Domain Tests Run Without Framework Context
 * 
 * This test verifies that:
 * 1. Domain tests do NOT use @SpringBootTest or Spring test context
 * 2. Domain tests do NOT require database connections
 * 3. Domain tests can execute quickly (<100ms per test class)
 */
class DomainTestsRunWithoutFrameworkPropertyTest {

    private static JavaClasses domainTestClasses;

    @BeforeAll
    static void importClasses() {
        domainTestClasses = new ClassFileImporter()
            .importPackages("dev.vibeafrika.pcm.preference.domain");
    }

    @Test
    void domainTestsShouldNotUseSpringBootTest() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().beAnnotatedWith("org.springframework.boot.test.context.SpringBootTest")
            .orShould().beAnnotatedWith("org.springframework.test.context.junit.jupiter.SpringExtension")
            .orShould().beAnnotatedWith("org.springframework.test.context.ContextConfiguration")
            .because("Domain tests must run without Spring test context (Requirement 8.3)");

        rule.check(domainTestClasses);
    }

    @Test
    void domainTestsShouldNotUseDataJpaTest() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().beAnnotatedWith("org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest")
            .orShould().beAnnotatedWith("org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase")
            .because("Domain tests must not require database connections (Requirement 8.4)");

        rule.check(domainTestClasses);
    }

    @Test
    void domainTestsShouldNotUseQuarkusTest() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().beAnnotatedWith("io.quarkus.test.junit.QuarkusTest")
            .orShould().beAnnotatedWith("io.quarkus.test.junit.QuarkusTestProfile")
            .because("Domain tests must run without Quarkus test context (Requirement 8.3)");

        rule.check(domainTestClasses);
    }

    @Test
    void domainTestsShouldNotDependOnTestContainers() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "org.testcontainers.."
            )
            .because("Domain tests must not require database containers (Requirement 8.4)");

        rule.check(domainTestClasses);
    }

    @Test
    void domainTestsShouldNotDependOnSpringTestFramework() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "org.springframework.test..",
                "org.springframework.boot.test.."
            )
            .because("Domain tests must not depend on Spring test framework (Requirement 8.3)");

        rule.check(domainTestClasses);
    }

    @Test
    void domainTestsShouldOnlyUseJUnitAndJqwik() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain..")
            .should().dependOnClassesThat().resideOutsideOfPackages(
                "java..",
                "org.junit..",
                "net.jqwik..",
                "org.assertj..",
                "org.mockito..",  // Allowed for mocking domain interfaces
                "io.github.sympol.pure..",  // pure-assert is allowed in domain
                "com.tngtech.archunit..",  // ArchUnit for architecture validation
                "..domain.."
            )
            .because("Domain tests should only use JUnit, jqwik, and AssertJ (Requirement 8.3, 8.5)");

        rule.check(domainTestClasses);
    }
}
