package dev.vibeafrika.pcm.consent.domain.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import dev.vibeafrika.pcm.consent.domain.model.Consent;
import dev.vibeafrika.pcm.consent.domain.model.ConsentId;
import dev.vibeafrika.pcm.consent.domain.model.ConsentPurpose;
import dev.vibeafrika.pcm.consent.domain.model.ConsentScope;
import dev.vibeafrika.pcm.consent.domain.model.ConsentStatus;
import dev.vibeafrika.pcm.consent.domain.model.ProfileId;
import dev.vibeafrika.pcm.consent.domain.model.TenantId;
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
 * Property-based test for Consent domain layer framework independence.
 *
 * Feature: framework-agnostic-domain, Property 1: Domain Layer Framework Independence
 *
 * Validates Requirements:
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
            .importPackages("dev.vibeafrika.pcm.consent.domain");
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
            .because("Consent domain layer must be framework-independent");

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
            .because("Consent domain layer must not depend on JPA/Hibernate");

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
            .because("Consent domain layer must not depend on web frameworks");

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
            .because("Consent domain uses pure-assert for validation, not framework validation");

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
            .because("Consent domain layer must only depend on Java stdlib and pure-assert ");

        rule.check(domainClasses);
    }

    /**
     * Property 1: Domain Layer Framework Independence - Runtime Verification
     *
     * Verifies that core Consent domain objects can be instantiated using plain Java
     * constructors/factory methods without any Spring ApplicationContext or
     * framework bootstrap. This is a runtime complement to the static ArchUnit checks.
     */
    @Property
    void consentDomainClassesCanBeInstantiatedWithoutFrameworkContext(
            @ForAll @NotBlank @StringLength(min = 1, max = 100) String tenantIdValue,
            @ForAll @NotBlank @StringLength(min = 3, max = 200) String purposeValue) {

        Assume.that(!tenantIdValue.isBlank());
        Assume.that(!purposeValue.isBlank());

        // TenantId - plain factory, no framework
        TenantId tenantId = TenantId.of(tenantIdValue);
        assertThat(tenantId).isNotNull();
        assertThat(tenantId.getValue()).isEqualTo(tenantIdValue);

        // ProfileId - plain factory, no framework
        UUID profileUuid = UUID.randomUUID();
        ProfileId profileId = ProfileId.of(profileUuid);
        assertThat(profileId).isNotNull();
        assertThat(profileId.getValue()).isEqualTo(profileUuid);

        // ConsentId - plain factory, no framework
        ConsentId consentId = ConsentId.generate();
        assertThat(consentId).isNotNull();
        assertThat(consentId.getValue()).isNotNull();

        // ConsentPurpose - plain factory, no framework
        ConsentPurpose purpose = ConsentPurpose.of(purposeValue);
        assertThat(purpose).isNotNull();
        assertThat(purpose.getValue()).isEqualTo(purposeValue);

        // Consent aggregate root - plain factory, no framework
        Consent consent = Consent.create(profileId, tenantId, purpose, ConsentScope.of("global"));
        assertThat(consent).isNotNull();
        assertThat(consent.getId()).isNotNull();
        assertThat(consent.getProfileId()).isEqualTo(profileId);
        assertThat(consent.getTenantId()).isEqualTo(tenantId);
        assertThat(consent.getPurpose()).isEqualTo(purpose);
        assertThat(consent.getStatus()).isEqualTo(ConsentStatus.GRANTED);
        assertThat(consent.isActive()).isTrue();
        assertThat(consent.getHistory()).hasSize(1);
    }

    /**
     * Verifies that ConsentId generation works without any framework context.
     */
    @Property
    void consentIdGenerationRequiresNoFramework() {
        ConsentId id1 = ConsentId.generate();
        ConsentId id2 = ConsentId.generate();

        assertThat(id1).isNotNull();
        assertThat(id2).isNotNull();
        assertThat(id1).isNotEqualTo(id2);
        assertThat(id1.getValue()).isNotNull();
    }
}
