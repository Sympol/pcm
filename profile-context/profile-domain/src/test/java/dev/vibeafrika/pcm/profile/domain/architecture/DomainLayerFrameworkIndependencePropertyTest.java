package dev.vibeafrika.pcm.profile.domain.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import dev.vibeafrika.pcm.profile.domain.model.Handle;
import dev.vibeafrika.pcm.profile.domain.model.Profile;
import dev.vibeafrika.pcm.profile.domain.model.ProfileId;
import dev.vibeafrika.pcm.profile.domain.model.TenantId;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Assume;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.NotBlank;
import net.jqwik.api.constraints.StringLength;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based test for Profile domain layer framework independence.
 *
 * Feature: framework-agnostic-domain, Property 1: Domain Layer Framework Independence
 *
 * Validates Requirements :
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
            .importPackages("dev.vibeafrika.pcm.profile.domain");
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
            .because("Profile domain layer must be framework-independent");

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
            .because("Profile domain layer must not depend on JPA/Hibernate");

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
            .because("Profile domain layer must not depend on web frameworks");

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
            .because("Profile domain uses pure-assert for validation, not framework validation");

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
            .because("Profile domain layer must only depend on Java stdlib and pure-assert");

        rule.check(domainClasses);
    }

    /**
     * Provides valid handle strings matching the pattern ^[a-z0-9_]{3,30}$
     */
    @Provide
    Arbitrary<String> validHandles() {
        return Arbitraries.strings()
            .withChars("abcdefghijklmnopqrstuvwxyz0123456789_")
            .ofMinLength(3)
            .ofMaxLength(30);
    }

    /**
     * Property 1: Domain Layer Framework Independence - Runtime Verification
     *
     * Verifies that core Profile domain objects can be instantiated using plain Java
     * constructors/factory methods without any Spring ApplicationContext or
     * framework bootstrap. This is a runtime complement to the static ArchUnit checks.
     */
    @Property
    void profileDomainClassesCanBeInstantiatedWithoutFrameworkContext(
            @ForAll @NotBlank @StringLength(min = 1, max = 100) String tenantIdValue,
            @ForAll("validHandles") String handleValue) {

        Assume.that(!tenantIdValue.isBlank());

        // TenantId - plain factory, no framework
        TenantId tenantId = TenantId.of(tenantIdValue);
        assertThat(tenantId).isNotNull();
        assertThat(tenantId.getValue()).isEqualTo(tenantIdValue);

        // ProfileId - plain factory, no framework
        UUID profileUuid = UUID.randomUUID();
        ProfileId profileId = ProfileId.of(profileUuid);
        assertThat(profileId).isNotNull();
        assertThat(profileId.getValue()).isEqualTo(profileUuid);

        // Handle - plain factory, no framework
        Handle handle = Handle.of(handleValue);
        assertThat(handle).isNotNull();
        assertThat(handle.getValue()).isEqualTo(handleValue);

        // Profile aggregate root - plain factory, no framework
        Profile profile = Profile.create(tenantId, handle, Map.of("key", "value"));
        assertThat(profile).isNotNull();
        assertThat(profile.getId()).isNotNull();
        assertThat(profile.getTenantId()).isEqualTo(tenantId);
        assertThat(profile.getHandle()).isEqualTo(handle);
        assertThat(profile.isDeleted()).isFalse();
        assertThat(profile.isActive()).isTrue();
    }

    /**
     * Verifies that ProfileId generation works without any framework context.
     */
    @Property
    void profileIdGenerationRequiresNoFramework() {
        ProfileId id1 = ProfileId.generate();
        ProfileId id2 = ProfileId.generate();

        assertThat(id1).isNotNull();
        assertThat(id2).isNotNull();
        assertThat(id1).isNotEqualTo(id2);
        assertThat(id1.getValue()).isNotNull();
    }

    /**
     * Verifies that Handle anonymization works without any framework context.
     */
    @Property
    void handleAnonymizationRequiresNoFramework() {
        Handle anonymized = Handle.anonymized();

        assertThat(anonymized).isNotNull();
        assertThat(anonymized.isAnonymized()).isTrue();
        assertThat(anonymized.getValue()).startsWith("deleted_");
    }
}
