package dev.vibeafrika.pcm.preference.domain.exception;

import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for Preference domain exception classes.
 *
 * Tests run WITHOUT Spring context — pure unit tests.
 */
class DomainExceptionTest {

    // =========================================================================
    // PreferenceDomainException (base class)
    // =========================================================================

    @Nested
    @DisplayName("PreferenceDomainException")
    class PreferenceDomainExceptionTests {

        /**
         * Concrete subclass for testing the abstract base.
         */
        static class ConcretePreferenceDomainException extends PreferenceDomainException {
            ConcretePreferenceDomainException(String message) {
                super(message);
            }

            ConcretePreferenceDomainException(String message, Throwable cause) {
                super(message, cause);
            }
        }

        @Test
        @DisplayName("extends RuntimeException (not a framework type)")
        void extendsRuntimeException() {
            PreferenceDomainException ex = new ConcretePreferenceDomainException("test");
            assertThat(ex).isInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("does NOT extend Error or checked Exception")
        void doesNotExtendCheckedExceptionOrError() {
            PreferenceDomainException ex = new ConcretePreferenceDomainException("test");
            assertThat(ex).isNotInstanceOf(Error.class);
            // RuntimeException is unchecked — verify it is NOT a checked exception
            // (i.e., not a direct subclass of Exception that is not RuntimeException)
            assertThat(ex).isInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("message constructor stores message correctly")
        void messageConstructor_storesMessage() {
            String message = "domain invariant violated";
            PreferenceDomainException ex = new ConcretePreferenceDomainException(message);
            assertThat(ex.getMessage()).isEqualTo(message);
        }

        @Test
        @DisplayName("message+cause constructor stores both message and cause")
        void messageCauseConstructor_storesBoth() {
            String message = "wrapped cause";
            Throwable cause = new IllegalStateException("root cause");
            PreferenceDomainException ex = new ConcretePreferenceDomainException(message, cause);
            assertThat(ex.getMessage()).isEqualTo(message);
            assertThat(ex.getCause()).isSameAs(cause);
        }

        @Test
        @DisplayName("can be thrown and caught as RuntimeException")
        void canBeThrownAndCaughtAsRuntimeException() {
            assertThatThrownBy(() -> {
                throw new ConcretePreferenceDomainException("thrown");
            }).isInstanceOf(RuntimeException.class)
              .hasMessage("thrown");
        }

        @Test
        @DisplayName("is not a Spring or framework-specific type")
        void isNotFrameworkSpecificType() {
            PreferenceDomainException ex = new ConcretePreferenceDomainException("test");
            String className = ex.getClass().getSuperclass().getName();
            assertThat(className).doesNotContain("springframework");
            assertThat(className).doesNotContain("jakarta");
            assertThat(className).doesNotContain("javax");
        }
    }

    // =========================================================================
    // PreferenceNotFoundException
    // =========================================================================

    @Nested
    @DisplayName("PreferenceNotFoundException")
    class PreferenceNotFoundExceptionTests {

        @Test
        @DisplayName("extends PreferenceDomainException")
        void extendsPreferenceDomainException() {
            PreferenceId id = PreferenceId.generate();
            PreferenceNotFoundException ex = new PreferenceNotFoundException(id);
            assertThat(ex).isInstanceOf(PreferenceDomainException.class);
        }

        @Test
        @DisplayName("extends RuntimeException (not a framework type)")
        void extendsRuntimeException() {
            PreferenceNotFoundException ex = new PreferenceNotFoundException(PreferenceId.generate());
            assertThat(ex).isInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("message contains the preference ID")
        void message_containsPreferenceId() {
            UUID uuid = UUID.randomUUID();
            PreferenceId id = PreferenceId.of(uuid);
            PreferenceNotFoundException ex = new PreferenceNotFoundException(id);
            assertThat(ex.getMessage()).contains(uuid.toString());
        }

        @Test
        @DisplayName("getPreferenceId() returns the original ID")
        void getPreferenceId_returnsOriginalId() {
            PreferenceId id = PreferenceId.generate();
            PreferenceNotFoundException ex = new PreferenceNotFoundException(id);
            assertThat(ex.getPreferenceId()).isEqualTo(id);
        }

        @Test
        @DisplayName("can be thrown and caught as PreferenceDomainException")
        void canBeThrownAndCaughtAsDomainException() {
            PreferenceId id = PreferenceId.generate();
            assertThatThrownBy(() -> {
                throw new PreferenceNotFoundException(id);
            }).isInstanceOf(PreferenceDomainException.class)
              .isInstanceOf(PreferenceNotFoundException.class);
        }

        @Test
        @DisplayName("message follows expected format 'Preference not found: <id>'")
        void message_followsExpectedFormat() {
            UUID uuid = UUID.randomUUID();
            PreferenceNotFoundException ex = new PreferenceNotFoundException(PreferenceId.of(uuid));
            assertThat(ex.getMessage()).startsWith("Preference not found:");
        }
    }

    // =========================================================================
    // PreferenceValidationException
    // =========================================================================

    @Nested
    @DisplayName("PreferenceValidationException")
    class PreferenceValidationExceptionTests {

        @Test
        @DisplayName("extends PreferenceDomainException")
        void extendsPreferenceDomainException() {
            PreferenceValidationException ex = new PreferenceValidationException("invalid value");
            assertThat(ex).isInstanceOf(PreferenceDomainException.class);
        }

        @Test
        @DisplayName("extends RuntimeException (not a framework type)")
        void extendsRuntimeException() {
            PreferenceValidationException ex = new PreferenceValidationException("invalid");
            assertThat(ex).isInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("message is stored and retrievable")
        void message_isStoredAndRetrievable() {
            String message = "Preference value exceeds maximum length";
            PreferenceValidationException ex = new PreferenceValidationException(message);
            assertThat(ex.getMessage()).isEqualTo(message);
        }

        @Test
        @DisplayName("can be thrown and caught as PreferenceDomainException")
        void canBeThrownAndCaughtAsDomainException() {
            assertThatThrownBy(() -> {
                throw new PreferenceValidationException("validation failed");
            }).isInstanceOf(PreferenceDomainException.class)
              .hasMessage("validation failed");
        }

        @Test
        @DisplayName("can be thrown and caught as RuntimeException")
        void canBeThrownAndCaughtAsRuntimeException() {
            assertThatThrownBy(() -> {
                throw new PreferenceValidationException("validation failed");
            }).isInstanceOf(RuntimeException.class);
        }
    }

    // =========================================================================
    // PreferenceDeletedException
    // =========================================================================

    @Nested
    @DisplayName("PreferenceDeletedException")
    class PreferenceDeletedExceptionTests {

        @Test
        @DisplayName("extends PreferenceDomainException")
        void extendsPreferenceDomainException() {
            PreferenceDeletedException ex = new PreferenceDeletedException("already deleted");
            assertThat(ex).isInstanceOf(PreferenceDomainException.class);
        }

        @Test
        @DisplayName("extends RuntimeException (not a framework type)")
        void extendsRuntimeException() {
            PreferenceDeletedException ex = new PreferenceDeletedException("deleted");
            assertThat(ex).isInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("message is stored and retrievable")
        void message_isStoredAndRetrievable() {
            String message = "Cannot update a deleted preference";
            PreferenceDeletedException ex = new PreferenceDeletedException(message);
            assertThat(ex.getMessage()).isEqualTo(message);
        }

        @Test
        @DisplayName("can be thrown and caught as PreferenceDomainException")
        void canBeThrownAndCaughtAsDomainException() {
            assertThatThrownBy(() -> {
                throw new PreferenceDeletedException("preference is deleted");
            }).isInstanceOf(PreferenceDomainException.class)
              .hasMessage("preference is deleted");
        }

        @Test
        @DisplayName("can be thrown and caught as RuntimeException")
        void canBeThrownAndCaughtAsRuntimeException() {
            assertThatThrownBy(() -> {
                throw new PreferenceDeletedException("preference is deleted");
            }).isInstanceOf(RuntimeException.class);
        }
    }

    // =========================================================================
    // Exception hierarchy cross-cutting concerns
    // =========================================================================

    @Nested
    @DisplayName("Exception hierarchy")
    class ExceptionHierarchyTests {

        @Test
        @DisplayName("all domain exceptions are subtypes of PreferenceDomainException")
        void allExceptions_areSubtypesOfPreferenceDomainException() {
            PreferenceId id = PreferenceId.generate();
            assertThat(new PreferenceNotFoundException(id))
                .isInstanceOf(PreferenceDomainException.class);
            assertThat(new PreferenceValidationException("msg"))
                .isInstanceOf(PreferenceDomainException.class);
            assertThat(new PreferenceDeletedException("msg"))
                .isInstanceOf(PreferenceDomainException.class);
        }

        @Test
        @DisplayName("all domain exceptions are unchecked (RuntimeException)")
        void allExceptions_areUnchecked() {
            PreferenceId id = PreferenceId.generate();
            assertThat(new PreferenceNotFoundException(id))
                .isInstanceOf(RuntimeException.class);
            assertThat(new PreferenceValidationException("msg"))
                .isInstanceOf(RuntimeException.class);
            assertThat(new PreferenceDeletedException("msg"))
                .isInstanceOf(RuntimeException.class);
        }

        @Test
        @DisplayName("no domain exception extends a framework-specific type")
        void noDomainException_extendsFrameworkType() {
            PreferenceId id = PreferenceId.generate();
            RuntimeException[] exceptions = {
                new PreferenceNotFoundException(id),
                new PreferenceValidationException("msg"),
                new PreferenceDeletedException("msg")
            };
            for (RuntimeException ex : exceptions) {
                Class<?> superClass = ex.getClass().getSuperclass();
                assertThat(superClass.getName())
                    .as("Superclass of %s should not be a framework type", ex.getClass().getSimpleName())
                    .doesNotContain("springframework")
                    .doesNotContain("jakarta")
                    .doesNotContain("javax");
            }
        }
    }
}
