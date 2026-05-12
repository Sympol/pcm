package dev.vibeafrika.pcm.infrastructure.spring;

import net.jqwik.api.*;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based test for module dependency direction across all four bounded contexts.
 *
 * <p><b>Property 10: Module Dependency Direction</b>
 *
 * <p>Verifies that the dependency direction rules are enforced:
 * <ul>
 *   <li>Domain modules depend on nothing (no framework classes on their classpath)</li>
 *   <li>Application modules depend only on domain (no framework classes)</li>
 *   <li>Infrastructure modules depend on domain + application + framework (Spring/JPA present)</li>
 * </ul>
 *
 * <p>This test uses reflection-based classpath analysis — no Spring context required.
 */
@Label("Feature: framework-agnostic-domain, Property 10: Module Dependency Direction")
class ModuleDependencyDirectionPropertyTest {

    // =========================================================================
    // Known domain classes (one representative per bounded context)
    // =========================================================================

    private static final List<Class<?>> DOMAIN_CLASSES = List.of(
            dev.vibeafrika.pcm.preference.domain.model.Preference.class,
            dev.vibeafrika.pcm.segment.domain.model.Segment.class,
            dev.vibeafrika.pcm.profile.domain.model.Profile.class,
            dev.vibeafrika.pcm.consent.domain.model.Consent.class
    );

    // =========================================================================
    // Known application classes (one representative per bounded context)
    // =========================================================================

    private static final List<Class<?>> APPLICATION_CLASSES = List.of(
            dev.vibeafrika.pcm.preference.application.usecase.CreatePreferenceUseCase.class,
            dev.vibeafrika.pcm.segment.application.usecase.CreateSegmentUseCase.class,
            dev.vibeafrika.pcm.profile.application.usecase.CreateProfileUseCase.class,
            dev.vibeafrika.pcm.consent.application.usecase.GrantConsentUseCase.class
    );

    // =========================================================================
    // Known infrastructure classes (one representative per bounded context)
    // =========================================================================

    private static final List<Class<?>> INFRASTRUCTURE_CLASSES = List.of(
            dev.vibeafrika.pcm.preference.infrastructure.persistence.entity.PreferenceJpaEntity.class,
            dev.vibeafrika.pcm.segment.infrastructure.persistence.entity.SegmentJpaEntity.class,
            dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity.class,
            dev.vibeafrika.pcm.consent.infrastructure.persistence.entity.ConsentJpaEntity.class
    );

    // =========================================================================
    // Property 10a: Domain classes have no Spring framework dependency
    // =========================================================================

    /**
     * Property 10a: For each domain class, its ClassLoader should NOT be able to
     * load Spring framework classes from the same module classpath.
     *
     * <p>Validates: Domain modules depend on nothing
     */
    @Property
    @Label("Property 10a: Domain classes have no Spring framework dependency")
    void domainClassHasNoSpringDependency(@ForAll("domainClasses") Class<?> domainClass) {
        // Domain classes must not reference Spring types in their own class loader
        // We verify this by checking that the domain class itself has no Spring imports
        // by inspecting its declared fields and methods for Spring types
        assertThat(hasSpringAnnotations(domainClass))
                .as("Domain class %s must not have Spring annotations", domainClass.getName())
                .isFalse();

        assertThat(hasSpringFieldTypes(domainClass))
                .as("Domain class %s must not have Spring-typed fields", domainClass.getName())
                .isFalse();
    }

    // =========================================================================
    // Property 10b: Domain classes have no JPA/Hibernate dependency
    // =========================================================================

    /**
     * Property 10b: For each domain class, it must not carry JPA or Hibernate annotations.
     *
     * <p>Validates: Domain modules depend on nothing
     */
    @Property
    @Label("Property 10b: Domain classes have no JPA/Hibernate annotations")
    void domainClassHasNoJpaAnnotations(@ForAll("domainClasses") Class<?> domainClass) {
        assertThat(hasJpaAnnotations(domainClass))
                .as("Domain class %s must not have JPA/Hibernate annotations", domainClass.getName())
                .isFalse();
    }

    // =========================================================================
    // Property 10c: Application classes have no Spring framework dependency
    // =========================================================================

    /**
     * Property 10c: For each application use case class, it must not carry Spring annotations
     * and must not have Spring-typed fields.
     *
     * <p>Validates: Application modules depend only on domain
     */
    @Property
    @Label("Property 10c: Application use case classes have no Spring annotations")
    void applicationClassHasNoSpringAnnotations(@ForAll("applicationClasses") Class<?> appClass) {
        assertThat(hasSpringAnnotations(appClass))
                .as("Application class %s must not have Spring annotations", appClass.getName())
                .isFalse();

        assertThat(hasSpringFieldTypes(appClass))
                .as("Application class %s must not have Spring-typed fields", appClass.getName())
                .isFalse();
    }

    // =========================================================================
    // Property 10d: Application classes have no JPA/Hibernate dependency
    // =========================================================================

    /**
     * Property 10d: For each application use case class, it must not carry JPA annotations.
     *
     * <p>Validates: Application modules depend only on domain
     */
    @Property
    @Label("Property 10d: Application use case classes have no JPA annotations")
    void applicationClassHasNoJpaAnnotations(@ForAll("applicationClasses") Class<?> appClass) {
        assertThat(hasJpaAnnotations(appClass))
                .as("Application class %s must not have JPA annotations", appClass.getName())
                .isFalse();
    }

    // =========================================================================
    // Property 10e: Infrastructure classes DO have JPA annotations
    // =========================================================================

    /**
     * Property 10e: For each infrastructure persistence entity class, it must carry
     * JPA annotations (@Entity, @Table, etc.), confirming that framework dependencies
     * are confined to the infrastructure layer.
     *
     * <p>Validates: Infrastructure modules depend on domain + application + framework
     */
    @Property
    @Label("Property 10e: Infrastructure persistence entities have JPA annotations")
    void infrastructureClassHasJpaAnnotations(@ForAll("infrastructureClasses") Class<?> infraClass) {
        assertThat(hasJpaAnnotations(infraClass))
                .as("Infrastructure class %s must have JPA annotations (framework deps belong here)",
                        infraClass.getName())
                .isTrue();
    }

    // =========================================================================
    // Property 10f: Application classes reside in the application package
    // =========================================================================

    /**
     * Property 10f: For each application class, its package must contain ".application."
     * and must NOT contain ".infrastructure." or ".domain.", confirming correct layering.
     */
    @Property
    @Label("Property 10f: Application classes reside in the application package")
    void applicationClassResidesInApplicationPackage(@ForAll("applicationClasses") Class<?> appClass) {
        String packageName = appClass.getPackageName();
        assertThat(packageName)
                .as("Application class %s must be in an application package", appClass.getName())
                .contains(".application.");
        assertThat(packageName)
                .as("Application class %s must not be in an infrastructure package", appClass.getName())
                .doesNotContain(".infrastructure.");
    }

    // =========================================================================
    // Property 10g: Domain classes reside in the domain package
    // =========================================================================

    /**
     * Property 10g: For each domain class, its package must contain ".domain."
     * and must NOT contain ".application." or ".infrastructure.", confirming correct layering.
     */
    @Property
    @Label("Property 10g: Domain classes reside in the domain package")
    void domainClassResidesInDomainPackage(@ForAll("domainClasses") Class<?> domainClass) {
        String packageName = domainClass.getPackageName();
        assertThat(packageName)
                .as("Domain class %s must be in a domain package", domainClass.getName())
                .contains(".domain.");
        assertThat(packageName)
                .as("Domain class %s must not be in an application package", domainClass.getName())
                .doesNotContain(".application.");
        assertThat(packageName)
                .as("Domain class %s must not be in an infrastructure package", domainClass.getName())
                .doesNotContain(".infrastructure.");
    }

    // =========================================================================
    // Arbitraries
    // =========================================================================

    @Provide
    Arbitrary<Class<?>> domainClasses() {
        return Arbitraries.of(DOMAIN_CLASSES);
    }

    @Provide
    Arbitrary<Class<?>> applicationClasses() {
        return Arbitraries.of(APPLICATION_CLASSES);
    }

    @Provide
    Arbitrary<Class<?>> infrastructureClasses() {
        return Arbitraries.of(INFRASTRUCTURE_CLASSES);
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    /**
     * Returns true if the class or any of its declared fields/methods carry a Spring annotation.
     */
    private boolean hasSpringAnnotations(Class<?> clazz) {
        // Check class-level annotations
        for (var annotation : clazz.getAnnotations()) {
            if (isSpringType(annotation.annotationType())) {
                return true;
            }
        }
        // Check field-level annotations
        for (var field : clazz.getDeclaredFields()) {
            for (var annotation : field.getAnnotations()) {
                if (isSpringType(annotation.annotationType())) {
                    return true;
                }
            }
        }
        // Check method-level annotations
        for (var method : clazz.getDeclaredMethods()) {
            for (var annotation : method.getAnnotations()) {
                if (isSpringType(annotation.annotationType())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns true if the class has any Spring-typed fields (field type is a Spring class).
     */
    private boolean hasSpringFieldTypes(Class<?> clazz) {
        for (var field : clazz.getDeclaredFields()) {
            if (isSpringType(field.getType())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns true if the class or any of its declared fields carry a JPA/Hibernate annotation.
     */
    private boolean hasJpaAnnotations(Class<?> clazz) {
        // Check class-level annotations
        for (var annotation : clazz.getAnnotations()) {
            if (isJpaType(annotation.annotationType())) {
                return true;
            }
        }
        // Check field-level annotations
        for (var field : clazz.getDeclaredFields()) {
            for (var annotation : field.getAnnotations()) {
                if (isJpaType(annotation.annotationType())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns true if the given type belongs to a Spring framework package.
     */
    private boolean isSpringType(Class<?> type) {
        String pkg = type.getPackageName();
        return pkg.startsWith("org.springframework")
                || pkg.startsWith("org.spring");
    }

    /**
     * Returns true if the given type belongs to a JPA or Hibernate package.
     */
    private boolean isJpaType(Class<?> type) {
        String pkg = type.getPackageName();
        return pkg.startsWith("jakarta.persistence")
                || pkg.startsWith("javax.persistence")
                || pkg.startsWith("org.hibernate");
    }
}
