package dev.vibeafrika.pcm.profile.application.architecture;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Property tests for Profile application layer use case independence.
 *
 * Property 6: Application Layer Framework Independence
 * Property 7: Use Cases Depend Only on Domain Contracts
 * Property 9: Use Cases Are Transaction-Annotation-Free
 *
 */
class UseCaseIndependencePropertyTest {

    private static JavaClasses applicationClasses;

    @BeforeAll
    static void importClasses() {
        applicationClasses = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.vibeafrika.pcm.profile.application");
    }

    // -------------------------------------------------------------------------
    // Property 6: Application Layer Framework Independence
    // -------------------------------------------------------------------------

    @Test
    void applicationLayerShouldNotDependOnSpring() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..profile.application..")
            .should().dependOnClassesThat().resideInAPackage("org.springframework..")
            .because("Application layer must have zero Spring dependencies ");

        rule.check(applicationClasses);
    }

    @Test
    void applicationLayerShouldNotDependOnJpa() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..profile.application..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "jakarta.persistence..",
                "javax.persistence..",
                "org.hibernate.."
            )
            .because("Application layer must have zero JPA/Hibernate dependencies");

        rule.check(applicationClasses);
    }

    @Test
    void applicationLayerShouldNotDependOnQuarkus() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..profile.application..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "io.quarkus..",
                "jakarta.ws.rs..",
                "jakarta.enterprise.."
            )
            .because("Application layer must have zero Quarkus/CDI dependencies");

        rule.check(applicationClasses);
    }

    @Test
    void applicationLayerShouldNotDependOnWebFrameworks() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..profile.application..")
            .should().dependOnClassesThat().resideInAnyPackage(
                "jakarta.servlet..",
                "javax.servlet.."
            )
            .because("Application layer must have zero web framework dependencies");

        rule.check(applicationClasses);
    }


    // -------------------------------------------------------------------------
    // Property 7: Use Cases Depend Only on Domain Contracts
    // -------------------------------------------------------------------------

    @Test
    void useCasesShouldOnlyDependOnDomainAndApplicationContracts() {
        ArchRule rule = classes()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should().onlyDependOnClassesThat().resideInAnyPackage(
                "java..",
                "..profile.domain..",
                "..profile.application.dto..",
                "..profile.application.config..",
                "..profile.application.port.."
            )
            .because("Use cases must only depend on domain contracts");

        rule.check(applicationClasses);
    }

    @Test
    void useCasesShouldHavePublicConstructor() {
        ArchRule rule = classes()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should(haveAtLeastOnePublicConstructor())
            .because("Use cases must be instantiable via constructor injection");

        rule.check(applicationClasses);
    }

    @Test
    void useCaseConstructorsShouldNotHaveSpringAnnotations() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should().beAnnotatedWith("org.springframework.beans.factory.annotation.Autowired")
            .orShould().beAnnotatedWith("org.springframework.stereotype.Component")
            .orShould().beAnnotatedWith("org.springframework.stereotype.Service")
            .because("Use case constructors must not use Spring DI annotations");

        rule.check(applicationClasses);
    }

    @Test
    void useCaseConstructorsShouldNotHaveJakartaInjectAnnotations() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should().beAnnotatedWith("jakarta.inject.Inject")
            .orShould().beAnnotatedWith("javax.inject.Inject")
            .because("Use case constructors must not use CDI inject annotations");

        rule.check(applicationClasses);
    }

    @Test
    void useCasesShouldBeInstantiableWithoutFramework() {
        ArchRule rule = classes()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should(beInstantiableWithoutFramework())
            .because("Use cases must be testable without framework context");

        rule.check(applicationClasses);
    }


    // -------------------------------------------------------------------------
    // Property 9: Use Cases Are Transaction-Annotation-Free
    // -------------------------------------------------------------------------

    @Test
    void useCasesShouldNotHaveTransactionalAnnotation() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should().beAnnotatedWith("org.springframework.transaction.annotation.Transactional")
            .because("Use cases must not use @Transactional - transactions are managed by infrastructure");

        rule.check(applicationClasses);
    }

    @Test
    void useCaseMethodsShouldNotHaveTransactionalAnnotation() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should(haveNoTransactionalAnnotationOnMethods())
            .because("Use case methods must not use @Transactional");

        rule.check(applicationClasses);
    }

    @Test
    void useCasesShouldNotHaveJakartaTransactionalAnnotation() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should().beAnnotatedWith("jakarta.transaction.Transactional")
            .orShould().beAnnotatedWith("javax.transaction.Transactional")
            .because("Use cases must not use Jakarta @Transactional");

        rule.check(applicationClasses);
    }

    // -------------------------------------------------------------------------
    // Custom ArchUnit conditions
    // -------------------------------------------------------------------------

    private static ArchCondition<JavaClass> haveAtLeastOnePublicConstructor() {
        return new ArchCondition<>("have at least one public constructor") {
            @Override
            public void check(JavaClass javaClass, ConditionEvents events) {
                boolean hasPublicConstructor = javaClass.getConstructors().stream()
                    .anyMatch(c -> c.getModifiers().contains(com.tngtech.archunit.core.domain.JavaModifier.PUBLIC));

                if (!hasPublicConstructor) {
                    events.add(SimpleConditionEvent.violated(javaClass,
                        String.format("Class %s has no public constructor", javaClass.getName())));
                }
            }
        };
    }

    private static ArchCondition<JavaClass> beInstantiableWithoutFramework() {
        return new ArchCondition<>("be instantiable without framework") {
            @Override
            public void check(JavaClass javaClass, ConditionEvents events) {
                try {
                    Class<?> clazz = Class.forName(javaClass.getName());
                    boolean hasUsableConstructor = false;

                    for (Constructor<?> constructor : clazz.getDeclaredConstructors()) {
                        if (!Modifier.isPublic(constructor.getModifiers())) continue;

                        boolean allParamsAcceptable = true;
                        for (Class<?> paramType : constructor.getParameterTypes()) {
                            // Accept: interfaces, primitives, java.* types, domain types
                            boolean acceptable = paramType.isInterface()
                                || paramType.isPrimitive()
                                || paramType.getName().startsWith("java.")
                                || paramType.getName().contains(".domain.")
                                || paramType.getName().contains(".application.port.");
                            if (!acceptable) {
                                allParamsAcceptable = false;
                                break;
                            }
                        }
                        if (allParamsAcceptable) {
                            hasUsableConstructor = true;
                            break;
                        }
                    }

                    if (!hasUsableConstructor) {
                        events.add(SimpleConditionEvent.violated(javaClass,
                            String.format("Class %s cannot be instantiated without a framework container", javaClass.getName())));
                    }
                } catch (ClassNotFoundException e) {
                    events.add(SimpleConditionEvent.violated(javaClass, "Could not load class: " + e.getMessage()));
                }
            }
        };
    }

    private static ArchCondition<JavaClass> haveNoTransactionalAnnotationOnMethods() {
        return new ArchCondition<>("have no @Transactional annotation on methods") {
            @Override
            public void check(JavaClass javaClass, ConditionEvents events) {
                try {
                    Class<?> clazz = Class.forName(javaClass.getName());
                    for (Method method : clazz.getDeclaredMethods()) {
                        for (Annotation annotation : method.getAnnotations()) {
                            String annotationName = annotation.annotationType().getName();
                            if (annotationName.equals("org.springframework.transaction.annotation.Transactional")
                                || annotationName.equals("jakarta.transaction.Transactional")
                                || annotationName.equals("javax.transaction.Transactional")) {
                                events.add(SimpleConditionEvent.violated(javaClass,
                                    String.format("Method %s#%s has @Transactional annotation - transactions must be managed by infrastructure",
                                        javaClass.getName(), method.getName())));
                            }
                        }
                    }
                } catch (ClassNotFoundException e) {
                    events.add(SimpleConditionEvent.violated(javaClass, "Could not load class: " + e.getMessage()));
                }
            }
        };
    }
}
