package dev.vibeafrika.pcm.preference.domain.repository;

import dev.vibeafrika.pcm.preference.domain.model.Preference;
import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import dev.vibeafrika.pcm.preference.domain.model.PreferenceKey;
import dev.vibeafrika.pcm.preference.domain.model.ProfileId;
import dev.vibeafrika.pcm.preference.domain.model.TenantId;
import net.jqwik.api.*;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for repository interface contracts.
 *
 *
 * Feature: framework-agnostic-domain, Property 4: Repository Interfaces Use Domain Types
 * Feature: framework-agnostic-domain, Property 5: Repository Interfaces Are Framework-Agnostic
 *
 * These tests use Java reflection to inspect the PreferenceRepository interface
 * at runtime and verify its structural properties.
 */
class RepositoryInterfaceContractsPropertyTest {

    private static final Class<?> REPOSITORY = PreferenceRepository.class;

    /**
     * The set of allowed domain types for method parameters and return types.
     * Only domain model types, Optional, void, and boolean are permitted.
     */
    private static final Set<Class<?>> ALLOWED_DOMAIN_TYPES = Set.of(
        Preference.class,
        PreferenceId.class,
        TenantId.class,
        PreferenceKey.class,
        ProfileId.class,
        Optional.class,
        boolean.class,
        Boolean.class,
        void.class,
        Void.class
    );

    /**
     * Forbidden framework interface name fragments that must not appear in the
     * superinterface hierarchy of a domain repository.
     */
    private static final Set<String> FORBIDDEN_FRAMEWORK_INTERFACES = Set.of(
        "org.springframework.data.repository.Repository",
        "org.springframework.data.repository.CrudRepository",
        "org.springframework.data.jpa.repository.JpaRepository",
        "org.springframework.data.repository.PagingAndSortingRepository",
        "org.springframework.data.repository.ListCrudRepository",
        "org.springframework.data.repository.ListPagingAndSortingRepository",
        "io.quarkus.hibernate.orm.panache.PanacheRepository",
        "io.quarkus.hibernate.orm.panache.PanacheRepositoryBase",
        "io.micronaut.data.repository.CrudRepository",
        "io.micronaut.data.repository.PageableRepository"
    );

    /**
     * Forbidden annotation name fragments that must not appear on the repository interface.
     */
    private static final Set<String> FORBIDDEN_ANNOTATION_PACKAGES = Set.of(
        "org.springframework.",
        "jakarta.persistence.",
        "javax.persistence.",
        "org.hibernate.",
        "jakarta.transaction.",
        "javax.transaction.",
        "io.quarkus.",
        "io.micronaut."
    );

    // =========================================================================
    // Property 4: Repository Interfaces Use Domain Types
    // =========================================================================

    /**
     * Property: Every method parameter in PreferenceRepository uses a domain type.
     *
     */
    @Property(tries = 1)
    @Label("Feature: framework-agnostic-domain, Property 4: All method parameters use domain types")
    void allMethodParametersUseDomainTypes() {
        for (Method method : REPOSITORY.getDeclaredMethods()) {
            for (Class<?> paramType : method.getParameterTypes()) {
                assertThat(isAllowedType(paramType))
                    .as("Method '%s' has parameter of type '%s' which is not a domain type. "
                            + "Repository methods must only accept domain types.",
                        method.getName(), paramType.getName())
                    .isTrue();
            }
        }
    }

    /**
     * Property: Every method return type in PreferenceRepository uses a domain type.
     *
     */
    @Property(tries = 1)
    @Label("Feature: framework-agnostic-domain, Property 4: All return types use domain types")
    void allReturnTypesUseDomainTypes() {
        for (Method method : REPOSITORY.getDeclaredMethods()) {
            Class<?> returnType = method.getReturnType();

            // For Optional<T>, also check the generic type argument T
            if (returnType.equals(Optional.class)) {
                Type genericReturn = method.getGenericReturnType();
                if (genericReturn instanceof ParameterizedType pt) {
                    Type typeArg = pt.getActualTypeArguments()[0];
                    if (typeArg instanceof Class<?> typeArgClass) {
                        assertThat(isAllowedType(typeArgClass))
                            .as("Method '%s' returns Optional<%s> which is not a domain type. "
                                    + "Repository methods must return domain types.",
                                method.getName(), typeArgClass.getName())
                            .isTrue();
                    }
                }
            } else {
                assertThat(isAllowedType(returnType))
                    .as("Method '%s' returns '%s' which is not a domain type. "
                            + "Repository methods must return domain types.",
                        method.getName(), returnType.getName())
                    .isTrue();
            }
        }
    }

    /**
     * Property: PreferenceRepository does not use raw primitives (String, UUID, int, long)
     * as method parameters — it must use domain value objects instead.
     *
     */
    @Property(tries = 1)
    @Label("Feature: framework-agnostic-domain, Property 4: No raw primitives in method parameters")
    void noRawPrimitivesInMethodParameters() {
        Set<Class<?>> forbiddenPrimitives = Set.of(
            String.class, UUID.class,
            int.class, Integer.class,
            long.class, Long.class
        );

        for (Method method : REPOSITORY.getDeclaredMethods()) {
            for (Class<?> paramType : method.getParameterTypes()) {
                assertThat(forbiddenPrimitives)
                    .as("Method '%s' has parameter of raw type '%s'. "
                            + "Use domain value objects instead of raw primitives.",
                        method.getName(), paramType.getName())
                    .doesNotContain(paramType);
            }
        }
    }

    // =========================================================================
    // Property 5: Repository Interfaces Are Framework-Agnostic
    // =========================================================================

    /**
     * Property: PreferenceRepository does not extend any Spring Data or other
     * framework-specific repository interfaces.
     *
     */
    @Property(tries = 1)
    @Label("Feature: framework-agnostic-domain, Property 5: Repository does not extend framework interfaces")
    void repositoryDoesNotExtendFrameworkInterfaces() {
        Set<String> allSuperInterfaces = collectAllSuperInterfaces(REPOSITORY);

        for (String forbidden : FORBIDDEN_FRAMEWORK_INTERFACES) {
            assertThat(allSuperInterfaces)
                .as("PreferenceRepository must not extend '%s'. "
                        + "Domain repositories must be plain Java interfaces.",
                    forbidden)
                .doesNotContain(forbidden);
        }
    }

    /**
     * Property: PreferenceRepository has no Spring, JPA, or other framework annotations.
     *
     */
    @Property(tries = 1)
    @Label("Feature: framework-agnostic-domain, Property 5: Repository has no framework annotations")
    void repositoryHasNoFrameworkAnnotations() {
        // Check class-level annotations
        for (Annotation annotation : REPOSITORY.getAnnotations()) {
            String annotationName = annotation.annotationType().getName();
            assertThat(isFrameworkAnnotation(annotationName))
                .as("PreferenceRepository has framework annotation '@%s'. "
                        + "Domain repositories must be plain Java interfaces.",
                    annotationName)
                .isFalse();
        }

        // Check method-level annotations
        for (Method method : REPOSITORY.getDeclaredMethods()) {
            for (Annotation annotation : method.getAnnotations()) {
                String annotationName = annotation.annotationType().getName();
                assertThat(isFrameworkAnnotation(annotationName))
                    .as("Method '%s' in PreferenceRepository has framework annotation '@%s'. "
                            + "Domain repositories must be plain Java interfaces.",
                        method.getName(), annotationName)
                    .isFalse();
            }
        }
    }

    /**
     * Property: PreferenceRepository is a plain Java interface (not a class or enum).
     *
     */
    @Property(tries = 1)
    @Label("Feature: framework-agnostic-domain, Property 5: Repository is a plain Java interface")
    void repositoryIsAPlainJavaInterface() {
        assertThat(REPOSITORY.isInterface())
            .as("PreferenceRepository must be a plain Java interface.")
            .isTrue();

        assertThat(REPOSITORY.isAnnotation())
            .as("PreferenceRepository must not be an annotation type.")
            .isFalse();

        assertThat(REPOSITORY.isEnum())
            .as("PreferenceRepository must not be an enum.")
            .isFalse();
    }

    /**
     * Property: PreferenceRepository resides in the domain layer package.
     *
     */
    @Property(tries = 1)
    @Label("Feature: framework-agnostic-domain, Property 5: Repository resides in domain layer")
    void repositoryResidesInDomainLayer() {
        String packageName = REPOSITORY.getPackageName();
        assertThat(packageName)
            .as("PreferenceRepository must reside in the domain layer package.")
            .startsWith("dev.vibeafrika.pcm.preference.domain");
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    /**
     * Returns true if the given type is an allowed domain type for repository method
     * signatures (parameters or return types).
     */
    private boolean isAllowedType(Class<?> type) {
        return ALLOWED_DOMAIN_TYPES.contains(type);
    }

    /**
     * Recursively collects all super-interface names for the given class/interface.
     */
    private Set<String> collectAllSuperInterfaces(Class<?> clazz) {
        java.util.HashSet<String> result = new java.util.HashSet<>();
        for (Class<?> iface : clazz.getInterfaces()) {
            result.add(iface.getName());
            result.addAll(collectAllSuperInterfaces(iface));
        }
        return result;
    }

    /**
     * Returns true if the annotation name belongs to a framework package.
     */
    private boolean isFrameworkAnnotation(String annotationName) {
        return FORBIDDEN_ANNOTATION_PACKAGES.stream()
            .anyMatch(annotationName::startsWith);
    }
}
