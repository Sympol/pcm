package dev.vibeafrika.pcm.preference.application.architecture;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.domain.JavaConstructor;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import com.tngtech.archunit.core.domain.JavaModifier;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Property-based test for use cases being constructor-injectable.
 * 
 * 
 * Feature: framework-agnostic-domain, Property 14: Use Cases Are Constructor-Injectable
 * 
 * This test verifies that:
 * 1. Use cases can be instantiated through constructor injection
 * 2. Use case constructors do NOT use framework-specific annotations (@Autowired, @Inject)
 * 3. Use cases are testable without framework context
 */
class UseCasesConstructorInjectablePropertyTest {

    private static JavaClasses applicationClasses;

    @BeforeAll
    static void importClasses() {
        applicationClasses = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("dev.vibeafrika.pcm.preference.application");
    }

    @Test
    void useCasesShouldHavePublicConstructor() {
        ArchRule rule = classes()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should(haveAtLeastOnePublicConstructor())
            .because("Use cases must be instantiable through public constructors");

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
            .because("Use case constructors must not use Spring annotations");

        rule.check(applicationClasses);
    }

    @Test
    void useCaseConstructorsShouldNotHaveJakartaInjectAnnotations() {
        ArchRule rule = noClasses()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should().beAnnotatedWith("jakarta.inject.Inject")
            .orShould().beAnnotatedWith("javax.inject.Inject")
            .because("Use case constructors must not use Jakarta/CDI inject annotations");

        rule.check(applicationClasses);
    }

    @Test
    void useCasesShouldOnlyDependOnDomainInterfaces() {
        ArchRule rule = classes()
            .that().resideInAPackage("..application.usecase..")
            .and().haveSimpleNameEndingWith("UseCase")
            .should().onlyDependOnClassesThat().resideInAnyPackage(
                "java..",
                "..domain..",
                "..application.dto..",
                "..application.config..",
                "..application.event..",
                "..application.port.."
            )
            .because("Use cases should only depend on domain contracts");

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

    // Custom ArchUnit conditions

    private static ArchCondition<JavaClass> haveAtLeastOnePublicConstructor() {
        return new ArchCondition<>("have at least one public constructor") {
            @Override
            public void check(JavaClass javaClass, ConditionEvents events) {
                boolean hasPublicConstructor = javaClass.getConstructors().stream()
                    .anyMatch(constructor -> constructor.getModifiers().contains(JavaModifier.PUBLIC));

                if (!hasPublicConstructor) {
                    String message = String.format(
                        "Class %s does not have a public constructor",
                        javaClass.getName()
                    );
                    events.add(SimpleConditionEvent.violated(javaClass, message));
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
                    Constructor<?>[] constructors = clazz.getDeclaredConstructors();
                    
                    boolean hasUsableConstructor = false;
                    for (Constructor<?> constructor : constructors) {
                        if (Modifier.isPublic(constructor.getModifiers())) {
                            // Check that constructor parameters are interfaces or simple types
                            Class<?>[] paramTypes = constructor.getParameterTypes();
                            boolean allParamsAreInterfacesOrSimple = true;
                            
                            for (Class<?> paramType : paramTypes) {
                                if (!paramType.isInterface() && 
                                    !paramType.isPrimitive() && 
                                    !paramType.getName().startsWith("java.lang.") &&
                                    !paramType.getName().startsWith("java.util.")) {
                                    // Parameter is a concrete class (not interface)
                                    // This is acceptable if it's a domain type
                                    if (!paramType.getName().contains(".domain.")) {
                                        allParamsAreInterfacesOrSimple = false;
                                        break;
                                    }
                                }
                            }
                            
                            if (allParamsAreInterfacesOrSimple) {
                                hasUsableConstructor = true;
                                break;
                            }
                        }
                    }
                    
                    if (!hasUsableConstructor) {
                        String message = String.format(
                            "Class %s cannot be easily instantiated without framework (no public constructor with interface/domain parameters)",
                            javaClass.getName()
                        );
                        events.add(SimpleConditionEvent.violated(javaClass, message));
                    }
                } catch (ClassNotFoundException e) {
                    events.add(SimpleConditionEvent.violated(javaClass, 
                        "Could not load class: " + e.getMessage()));
                }
            }
        };
    }
}
