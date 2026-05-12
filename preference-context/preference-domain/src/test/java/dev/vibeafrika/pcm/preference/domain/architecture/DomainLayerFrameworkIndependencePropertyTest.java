package dev.vibeafrika.pcm.preference.domain.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import dev.vibeafrika.pcm.preference.domain.model.Preference;
import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import dev.vibeafrika.pcm.preference.domain.model.PreferenceKey;
import dev.vibeafrika.pcm.preference.domain.model.ProfileId;
import dev.vibeafrika.pcm.preference.domain.model.TenantId;
import net.jqwik.api.Assume;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.NotBlank;
import net.jqwik.api.constraints.StringLength;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based test for domain layer framework independence.
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
            .because("Domain layer must be framework-independent");

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
            .because("Domain layer must not depend on JPA/Hibernate");

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
            .because("Domain layer must not depend on web frameworks");

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
            .because("Domain layer must only depend on Java stdlib and pure-assert");

        rule.check(domainClasses);
    }

    /**
     * Property 1: Domain Layer Framework Independence - Runtime Verification
     *
     * Verifies that core domain objects can be instantiated using plain Java
     * constructors/factory methods without any Spring ApplicationContext or
     * framework bootstrap. This is a runtime complement to the static ArchUnit checks.
     */
    @Property
    void domainClassesCanBeInstantiatedWithoutFrameworkContext(
            @ForAll @NotBlank @StringLength(min = 1, max = 100) String tenantIdValue,
            @ForAll @NotBlank @StringLength(min = 1, max = 100) String preferenceKeyValue) {

        // Skip whitespace-only strings that pass @NotBlank but fail pure-assert's .notBlank()
        Assume.that(!tenantIdValue.isBlank());
        Assume.that(!preferenceKeyValue.isBlank());

        // TenantId - plain factory, no framework
        TenantId tenantId = TenantId.of(tenantIdValue);
        assertThat(tenantId).isNotNull();
        assertThat(tenantId.getValue()).isEqualTo(tenantIdValue);

        // ProfileId - plain factory, no framework
        UUID profileUuid = UUID.randomUUID();
        ProfileId profileId = ProfileId.of(profileUuid);
        assertThat(profileId).isNotNull();
        assertThat(profileId.getValue()).isEqualTo(profileUuid);

        // PreferenceId - plain factory, no framework
        PreferenceId preferenceId = PreferenceId.generate();
        assertThat(preferenceId).isNotNull();
        assertThat(preferenceId.getValue()).isNotNull();

        // PreferenceKey - plain factory, no framework
        PreferenceKey preferenceKey = PreferenceKey.of(preferenceKeyValue);
        assertThat(preferenceKey).isNotNull();
        assertThat(preferenceKey.getValue()).isEqualTo(preferenceKeyValue);

        // Preference aggregate root - plain factory, no framework
        Preference preference = Preference.create(tenantId, profileId);
        assertThat(preference).isNotNull();
        assertThat(preference.getId()).isNotNull();
        assertThat(preference.getTenantId()).isEqualTo(tenantId);
        assertThat(preference.getProfileId()).isEqualTo(profileId);
        assertThat(preference.isDeleted()).isFalse();
    }
}
