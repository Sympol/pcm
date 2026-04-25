package dev.vibeafrika.pcm.segment.domain.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import dev.vibeafrika.pcm.segment.domain.model.ProfileId;
import dev.vibeafrika.pcm.segment.domain.model.Segment;
import dev.vibeafrika.pcm.segment.domain.model.SegmentId;
import dev.vibeafrika.pcm.segment.domain.model.TenantId;
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
 * Property-based test for Segment domain layer framework independence.
 *
 * Feature: framework-agnostic-domain, Property 1: Domain Layer Framework Independence
 *
 * Validates Requirements:
 * - Domain layer has ZERO dependencies on Spring Framework
 * - Domain layer has ZERO dependencies on JPA/Hibernate
 * - Domain layer has ZERO dependencies on any web framework
 * - Domain entities use only standard Java features
 */
class DomainLayerFrameworkIndependencePropertyTest {

    private static JavaClasses domainClasses;

    @BeforeAll
    static void importClasses() {
        domainClasses = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.vibeafrika.pcm.segment.domain");
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
            .because("Segment domain layer must be framework-independent");

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
            .because("Segment domain layer must not depend on JPA/Hibernate");

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
            .because("Segment domain layer must not depend on web frameworks");

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
            .because("Segment domain uses pure-assert for validation, not framework validation");

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
            .because("Segment domain layer must only depend on Java stdlib and pure-assert");

        rule.check(domainClasses);
    }

    /**
     * Property 1: Domain Layer Framework Independence - Runtime Verification
     *
     * Verifies that core Segment domain objects can be instantiated using plain Java
     * constructors/factory methods without any Spring ApplicationContext or
     * framework bootstrap. This is a runtime complement to the static ArchUnit checks.
     */
    @Property
    void segmentDomainClassesCanBeInstantiatedWithoutFrameworkContext(
            @ForAll @NotBlank @StringLength(min = 1, max = 100) String tenantIdValue) {

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

        // SegmentId - plain factory, no framework
        SegmentId segmentId = SegmentId.generate();
        assertThat(segmentId).isNotNull();
        assertThat(segmentId.getValue()).isNotNull();

        // Segment aggregate root - plain factory, no framework
        Segment segment = Segment.create(tenantId, profileId);
        assertThat(segment).isNotNull();
        assertThat(segment.getId()).isNotNull();
        assertThat(segment.getTenantId()).isEqualTo(tenantId);
        assertThat(segment.getProfileId()).isEqualTo(profileId);
        assertThat(segment.getTags()).isEmpty();
        assertThat(segment.getScores()).isEmpty();
    }

    /**
     * Verifies that SegmentId generation works without any framework context.
     */
    @Property
    void segmentIdGenerationRequiresNoFramework() {
        SegmentId id1 = SegmentId.generate();
        SegmentId id2 = SegmentId.generate();

        assertThat(id1).isNotNull();
        assertThat(id2).isNotNull();
        assertThat(id1).isNotEqualTo(id2);
        assertThat(id1.getValue()).isNotNull();
    }
}
