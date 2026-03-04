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
 * Property-based test for domain entities being annotation-free.
 * 
 * **Validates: Requirements 2.1, 2.2, 2.3**
 * 
 * Feature: framework-agnostic-domain, Property 2: Domain Entities Are Annotation-Free
 * 
 * This test verifies that:
 * 1. Domain entities have NO JPA annotations (@Entity, @Id, @Column, @Table, @ManyToOne, @OneToMany)
 * 2. Domain entities have NO Spring annotations (@Component, @Service, @Autowired)
 * 3. Domain entities have NO validation framework annotations (@NotNull, @Size, @Valid)
 */
class DomainEntitiesAnnotationFreePropertyTest {

    private static JavaClasses domainClasses;

    @BeforeAll
    static void importClasses() {
        domainClasses = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.vibeafrika.pcm.preference.domain");
    }

    @Test
    void domainEntitiesShouldNotHaveJPAAnnotations() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain.model..")
            .should().beAnnotatedWith("jakarta.persistence.Entity")
            .orShould().beAnnotatedWith("javax.persistence.Entity")
            .orShould().beAnnotatedWith("jakarta.persistence.Id")
            .orShould().beAnnotatedWith("jakarta.persistence.Column")
            .orShould().beAnnotatedWith("jakarta.persistence.Table")
            .orShould().beAnnotatedWith("jakarta.persistence.ManyToOne")
            .orShould().beAnnotatedWith("jakarta.persistence.OneToMany")
            .orShould().beAnnotatedWith("jakarta.persistence.ManyToMany")
            .orShould().beAnnotatedWith("jakarta.persistence.OneToOne")
            .because("Domain entities must not contain JPA annotations (Requirement 2.1)");

        rule.check(domainClasses);
    }

    @Test
    void domainEntitiesShouldNotHaveSpringAnnotations() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain.model..")
            .should().beAnnotatedWith("org.springframework.stereotype.Component")
            .orShould().beAnnotatedWith("org.springframework.stereotype.Service")
            .orShould().beAnnotatedWith("org.springframework.stereotype.Repository")
            .orShould().beAnnotatedWith("org.springframework.beans.factory.annotation.Autowired")
            .orShould().beAnnotatedWith("org.springframework.context.annotation.Bean")
            .because("Domain entities must not contain Spring annotations (Requirement 2.2)");

        rule.check(domainClasses);
    }

    @Test
    void domainEntitiesShouldNotHaveValidationFrameworkAnnotations() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain.model..")
            .should().beAnnotatedWith("jakarta.validation.constraints.NotNull")
            .orShould().beAnnotatedWith("jakarta.validation.constraints.Size")
            .orShould().beAnnotatedWith("jakarta.validation.constraints.Valid")
            .orShould().beAnnotatedWith("jakarta.validation.constraints.NotBlank")
            .orShould().beAnnotatedWith("jakarta.validation.constraints.NotEmpty")
            .orShould().beAnnotatedWith("jakarta.validation.constraints.Min")
            .orShould().beAnnotatedWith("jakarta.validation.constraints.Max")
            .orShould().beAnnotatedWith("jakarta.validation.constraints.Pattern")
            .because("Domain entities must not contain validation framework annotations (Requirement 2.3)");

        rule.check(domainClasses);
    }

    @Test
    void domainEntitiesShouldNotHaveHibernateAnnotations() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain.model..")
            .should().beAnnotatedWith("org.hibernate.annotations.SQLDelete")
            .orShould().beAnnotatedWith("org.hibernate.annotations.SQLRestriction")
            .orShould().beAnnotatedWith("org.hibernate.annotations.Where")
            .orShould().beAnnotatedWith("org.hibernate.annotations.CreationTimestamp")
            .orShould().beAnnotatedWith("org.hibernate.annotations.UpdateTimestamp")
            .because("Domain entities must not contain Hibernate-specific annotations (Requirement 2.1)");

        rule.check(domainClasses);
    }

    @Test
    void domainEntitiesShouldNotHaveSpringDataAnnotations() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..domain.model..")
            .should().beAnnotatedWith("org.springframework.data.annotation.CreatedDate")
            .orShould().beAnnotatedWith("org.springframework.data.annotation.LastModifiedDate")
            .orShould().beAnnotatedWith("org.springframework.data.annotation.CreatedBy")
            .orShould().beAnnotatedWith("org.springframework.data.annotation.LastModifiedBy")
            .because("Domain entities must not contain Spring Data annotations (Requirement 2.2)");

        rule.check(domainClasses);
    }
}
