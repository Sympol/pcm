package dev.vibeafrika.pcm.infrastructure.spring;

import dev.vibeafrika.pcm.consent.infrastructure.persistence.entity.ConsentEventJpaEntity;
import dev.vibeafrika.pcm.consent.infrastructure.persistence.entity.ConsentJpaEntity;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.entity.PreferenceJpaEntity;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;
import dev.vibeafrika.pcm.segment.infrastructure.persistence.entity.SegmentJpaEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import net.jqwik.api.*;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based tests for infrastructure layer JPA annotation presence.
 *
 * <p><b>Property 12: Infrastructure Contains Framework Annotations</b>
 *
 * <p>Verifies that all JPA persistence entity classes in the infrastructure layer
 * carry the expected JPA annotations (@Entity, @Table, @Id, @Column) and do NOT
 * carry any domain-layer annotations. This is a pure reflection-based structural
 * test — no Spring context or Testcontainers required.
 *
 * <p>Sub-properties tested:
 * <ul>
 *   <li>12a: Each JPA entity class is annotated with {@code @Entity}</li>
 *   <li>12b: Each JPA entity class is annotated with {@code @Table}</li>
 *   <li>12c: Each JPA entity class has at least one field annotated with {@code @Id}</li>
 *   <li>12d: Each JPA entity class has at least one field annotated with {@code @Column}</li>
 *   <li>12e: Each JPA entity class has NO domain-layer annotations</li>
 * </ul>
 */
class InfrastructureAnnotationPropertyTest {

    // =========================================================================
    // Property 12a: JPA entity classes are annotated with @Entity
    // =========================================================================

    /**
     * Property 12a: For each known JPA entity class, it SHALL be annotated with
     * {@code @Entity} from {@code jakarta.persistence}.
     */
    @Property
    @Label("Property 12a: Each JPA entity class is annotated with @Entity")
    void jpaEntityClassHasEntityAnnotation(@ForAll("jpaEntityClasses") Class<?> entityClass) {
        assertThat(entityClass.isAnnotationPresent(Entity.class))
                .as("Class %s should be annotated with @Entity", entityClass.getName())
                .isTrue();
    }

    // =========================================================================
    // Property 12b: JPA entity classes are annotated with @Table
    // =========================================================================

    /**
     * Property 12b: For each known JPA entity class, it SHALL be annotated with
     * {@code @Table} from {@code jakarta.persistence}.
     */
    @Property
    @Label("Property 12b: Each JPA entity class is annotated with @Table")
    void jpaEntityClassHasTableAnnotation(@ForAll("jpaEntityClasses") Class<?> entityClass) {
        assertThat(entityClass.isAnnotationPresent(Table.class))
                .as("Class %s should be annotated with @Table", entityClass.getName())
                .isTrue();
    }

    // =========================================================================
    // Property 12c: JPA entity classes have at least one @Id field
    // =========================================================================

    /**
     * Property 12c: For each known JPA entity class, at least one field (including
     * inherited fields) SHALL be annotated with {@code @Id} from {@code jakarta.persistence}.
     */
    @Property
    @Label("Property 12c: Each JPA entity class has at least one @Id field")
    void jpaEntityClassHasIdField(@ForAll("jpaEntityClasses") Class<?> entityClass) {
        assertThat(hasFieldAnnotation(entityClass, Id.class))
                .as("Class %s should have at least one field annotated with @Id", entityClass.getName())
                .isTrue();
    }

    // =========================================================================
    // Property 12d: JPA entity classes have at least one @Column field
    // =========================================================================

    /**
     * Property 12d: For each known JPA entity class, at least one field (including
     * inherited fields) SHALL be annotated with {@code @Column} from {@code jakarta.persistence}.
     */
    @Property
    @Label("Property 12d: Each JPA entity class has at least one @Column field")
    void jpaEntityClassHasColumnField(@ForAll("jpaEntityClasses") Class<?> entityClass) {
        assertThat(hasFieldAnnotation(entityClass, Column.class))
                .as("Class %s should have at least one field annotated with @Column", entityClass.getName())
                .isTrue();
    }

    // =========================================================================
    // Property 12e: JPA entity classes have NO domain-layer annotations
    // =========================================================================

    /**
     * Property 12e: For each known JPA entity class, it SHALL NOT carry any
     * annotation whose package starts with a domain layer package pattern.
     * Infrastructure entities must not bleed domain concerns.
     */
    @Property
    @Label("Property 12e: Each JPA entity class has no domain-layer annotations")
    void jpaEntityClassHasNoDomainAnnotations(@ForAll("jpaEntityClasses") Class<?> entityClass) {
        for (Annotation annotation : entityClass.getAnnotations()) {
            String annotationPackage = annotation.annotationType().getPackageName();
            assertThat(annotationPackage)
                    .as("Class %s should not have domain-layer annotation %s",
                            entityClass.getName(), annotation.annotationType().getName())
                    .doesNotContain(".domain");
        }
    }

    // =========================================================================
    // Arbitraries
    // =========================================================================

    /**
     * Provides the known JPA entity classes from all bounded context infrastructure modules.
     */
    @Provide
    Arbitrary<Class<?>> jpaEntityClasses() {
        return Arbitraries.of(
                PreferenceJpaEntity.class,
                ProfileJpaEntity.class,
                SegmentJpaEntity.class,
                ConsentJpaEntity.class,
                ConsentEventJpaEntity.class
        );
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    /**
     * Checks whether any field in the given class (or any of its superclasses,
     * up to but not including {@code Object}) is annotated with the given annotation.
     *
     * @param clazz      the class to inspect
     * @param annotation the annotation to look for
     * @return {@code true} if at least one field carries the annotation
     */
    private boolean hasFieldAnnotation(Class<?> clazz,
                                       Class<? extends Annotation> annotation) {
        Class<?> current = clazz;
        while (current != null && current != Object.class) {
            for (Field field : current.getDeclaredFields()) {
                if (field.isAnnotationPresent(annotation)) {
                    return true;
                }
            }
            current = current.getSuperclass();
        }
        return false;
    }
}
