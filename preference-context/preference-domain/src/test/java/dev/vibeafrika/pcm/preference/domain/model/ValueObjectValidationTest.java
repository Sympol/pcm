package dev.vibeafrika.pcm.preference.domain.model;

import io.github.sympol.pure.asserts.AssertionException;
import io.github.sympol.pure.asserts.MissingMandatoryValueException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for Preference domain value objects.
 *
 * Covers:
 * - Valid construction (happy path)
 * - Validation rules and edge cases (null, blank, too long)
 * - Typed exceptions from pure-assert (AssertionException / MissingMandatoryValueException)
 * - equals() and hashCode() contracts
 *
 * Tests run WITHOUT Spring context — pure unit tests.
 *
 */
class ValueObjectValidationTest {

    // =========================================================================
    // PreferenceId
    // =========================================================================

    @Nested
    @DisplayName("PreferenceId")
    class PreferenceIdTests {

        @Test
        @DisplayName("accepts a valid UUID")
        void of_acceptsValidUUID() {
            UUID uuid = UUID.randomUUID();
            PreferenceId id = PreferenceId.of(uuid);
            assertThat(id.getValue()).isEqualTo(uuid);
        }

        @Test
        @DisplayName("generate() produces a non-null id")
        void generate_producesNonNullId() {
            PreferenceId id = PreferenceId.generate();
            assertThat(id).isNotNull();
            assertThat(id.getValue()).isNotNull();
        }

        @Test
        @DisplayName("generate() produces unique ids")
        void generate_producesUniqueIds() {
            PreferenceId id1 = PreferenceId.generate();
            PreferenceId id2 = PreferenceId.generate();
            assertThat(id1).isNotEqualTo(id2);
        }

        @Test
        @DisplayName("throws MissingMandatoryValueException (not IllegalArgumentException) for null")
        void of_throwsMissingMandatoryValueException_whenNull() {
            assertThatThrownBy(() -> PreferenceId.of(null))
                .isInstanceOf(MissingMandatoryValueException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("exception contains field name 'preferenceId'")
        void of_exceptionContainsFieldName_whenNull() {
            assertThatThrownBy(() -> PreferenceId.of(null))
                .isInstanceOf(AssertionException.class)
                .satisfies(ex -> {
                    AssertionException ae = (AssertionException) ex;
                    assertThat(ae.field()).isEqualTo("preferenceId");
                });
        }

        @Test
        @DisplayName("equals: same UUID → equal")
        void equals_sameUUID_isEqual() {
            UUID uuid = UUID.randomUUID();
            assertThat(PreferenceId.of(uuid)).isEqualTo(PreferenceId.of(uuid));
        }

        @Test
        @DisplayName("equals: different UUID → not equal")
        void equals_differentUUID_isNotEqual() {
            assertThat(PreferenceId.of(UUID.randomUUID()))
                .isNotEqualTo(PreferenceId.of(UUID.randomUUID()));
        }

        @Test
        @DisplayName("equals: same instance → equal")
        void equals_sameInstance_isEqual() {
            PreferenceId id = PreferenceId.generate();
            assertThat(id).isEqualTo(id);
        }

        @Test
        @DisplayName("equals: null → not equal")
        void equals_null_isNotEqual() {
            assertThat(PreferenceId.generate()).isNotEqualTo(null);
        }

        @Test
        @DisplayName("equals: different type → not equal")
        void equals_differentType_isNotEqual() {
            UUID uuid = UUID.randomUUID();
            assertThat(PreferenceId.of(uuid)).isNotEqualTo(uuid);
        }

        @Test
        @DisplayName("hashCode: equal objects have equal hashCode")
        void hashCode_equalObjects_haveSameHashCode() {
            UUID uuid = UUID.randomUUID();
            assertThat(PreferenceId.of(uuid).hashCode())
                .isEqualTo(PreferenceId.of(uuid).hashCode());
        }

        @Test
        @DisplayName("toString returns UUID string")
        void toString_returnsUUIDString() {
            UUID uuid = UUID.randomUUID();
            assertThat(PreferenceId.of(uuid).toString()).isEqualTo(uuid.toString());
        }
    }

    // =========================================================================
    // TenantId
    // =========================================================================

    @Nested
    @DisplayName("TenantId")
    class TenantIdTests {

        @Test
        @DisplayName("accepts a valid value")
        void of_acceptsValidValue() {
            TenantId tenantId = TenantId.of("acme-corp");
            assertThat(tenantId.getValue()).isEqualTo("acme-corp");
        }

        @Test
        @DisplayName("accepts exactly 100 characters (boundary)")
        void of_accepts100CharValue() {
            String exactly100 = "a".repeat(100);
            TenantId tenantId = TenantId.of(exactly100);
            assertThat(tenantId.getValue()).isEqualTo(exactly100);
        }

        @Test
        @DisplayName("throws AssertionException (not IllegalArgumentException) for null")
        void of_throwsAssertionException_whenNull() {
            assertThatThrownBy(() -> TenantId.of(null))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("throws AssertionException for blank string")
        void of_throwsAssertionException_whenBlank() {
            assertThatThrownBy(() -> TenantId.of("   "))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("throws AssertionException for empty string")
        void of_throwsAssertionException_whenEmpty() {
            assertThatThrownBy(() -> TenantId.of(""))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("throws AssertionException for value exceeding 100 characters")
        void of_throwsAssertionException_whenTooLong() {
            String tooLong = "a".repeat(101);
            assertThatThrownBy(() -> TenantId.of(tooLong))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("exception contains field name 'tenantId'")
        void of_exceptionContainsFieldName_whenBlank() {
            assertThatThrownBy(() -> TenantId.of(""))
                .isInstanceOf(AssertionException.class)
                .satisfies(ex -> {
                    AssertionException ae = (AssertionException) ex;
                    assertThat(ae.field()).isEqualTo("tenantId");
                });
        }

        @Test
        @DisplayName("equals: same value → equal")
        void equals_sameValue_isEqual() {
            assertThat(TenantId.of("tenant-a")).isEqualTo(TenantId.of("tenant-a"));
        }

        @Test
        @DisplayName("equals: different value → not equal")
        void equals_differentValue_isNotEqual() {
            assertThat(TenantId.of("tenant-a")).isNotEqualTo(TenantId.of("tenant-b"));
        }

        @Test
        @DisplayName("equals: same instance → equal")
        void equals_sameInstance_isEqual() {
            TenantId id = TenantId.of("tenant-x");
            assertThat(id).isEqualTo(id);
        }

        @Test
        @DisplayName("equals: null → not equal")
        void equals_null_isNotEqual() {
            assertThat(TenantId.of("tenant-a")).isNotEqualTo(null);
        }

        @Test
        @DisplayName("hashCode: equal objects have equal hashCode")
        void hashCode_equalObjects_haveSameHashCode() {
            assertThat(TenantId.of("tenant-a").hashCode())
                .isEqualTo(TenantId.of("tenant-a").hashCode());
        }

        @Test
        @DisplayName("toString returns the raw value")
        void toString_returnsRawValue() {
            assertThat(TenantId.of("my-tenant").toString()).isEqualTo("my-tenant");
        }
    }

    // =========================================================================
    // PreferenceKey
    // =========================================================================

    @Nested
    @DisplayName("PreferenceKey")
    class PreferenceKeyTests {

        @Test
        @DisplayName("accepts a valid key")
        void of_acceptsValidKey() {
            PreferenceKey key = PreferenceKey.of("theme");
            assertThat(key.getValue()).isEqualTo("theme");
        }

        @Test
        @DisplayName("accepts exactly 100 characters (boundary)")
        void of_accepts100CharKey() {
            String exactly100 = "k".repeat(100);
            PreferenceKey key = PreferenceKey.of(exactly100);
            assertThat(key.getValue()).isEqualTo(exactly100);
        }

        @Test
        @DisplayName("throws AssertionException (not IllegalArgumentException) for null")
        void of_throwsAssertionException_whenNull() {
            assertThatThrownBy(() -> PreferenceKey.of(null))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("throws AssertionException for blank string")
        void of_throwsAssertionException_whenBlank() {
            assertThatThrownBy(() -> PreferenceKey.of("   "))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("throws AssertionException for empty string")
        void of_throwsAssertionException_whenEmpty() {
            assertThatThrownBy(() -> PreferenceKey.of(""))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("throws AssertionException for value exceeding 100 characters")
        void of_throwsAssertionException_whenTooLong() {
            String tooLong = "k".repeat(101);
            assertThatThrownBy(() -> PreferenceKey.of(tooLong))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("exception contains field name 'preferenceKey'")
        void of_exceptionContainsFieldName_whenBlank() {
            assertThatThrownBy(() -> PreferenceKey.of(""))
                .isInstanceOf(AssertionException.class)
                .satisfies(ex -> {
                    AssertionException ae = (AssertionException) ex;
                    assertThat(ae.field()).isEqualTo("preferenceKey");
                });
        }

        @Test
        @DisplayName("equals: same value → equal")
        void equals_sameValue_isEqual() {
            assertThat(PreferenceKey.of("theme")).isEqualTo(PreferenceKey.of("theme"));
        }

        @Test
        @DisplayName("equals: different value → not equal")
        void equals_differentValue_isNotEqual() {
            assertThat(PreferenceKey.of("theme")).isNotEqualTo(PreferenceKey.of("language"));
        }

        @Test
        @DisplayName("equals: same instance → equal")
        void equals_sameInstance_isEqual() {
            PreferenceKey key = PreferenceKey.of("theme");
            assertThat(key).isEqualTo(key);
        }

        @Test
        @DisplayName("equals: null → not equal")
        void equals_null_isNotEqual() {
            assertThat(PreferenceKey.of("theme")).isNotEqualTo(null);
        }

        @Test
        @DisplayName("hashCode: equal objects have equal hashCode")
        void hashCode_equalObjects_haveSameHashCode() {
            assertThat(PreferenceKey.of("theme").hashCode())
                .isEqualTo(PreferenceKey.of("theme").hashCode());
        }

        @Test
        @DisplayName("toString returns the raw value")
        void toString_returnsRawValue() {
            assertThat(PreferenceKey.of("dark-mode").toString()).isEqualTo("dark-mode");
        }
    }

    // =========================================================================
    // ProfileId
    // =========================================================================

    @Nested
    @DisplayName("ProfileId")
    class ProfileIdTests {

        @Test
        @DisplayName("accepts a valid UUID")
        void of_acceptsValidUUID() {
            UUID uuid = UUID.randomUUID();
            ProfileId id = ProfileId.of(uuid);
            assertThat(id.getValue()).isEqualTo(uuid);
        }

        @Test
        @DisplayName("generate() produces a non-null id")
        void generate_producesNonNullId() {
            ProfileId id = ProfileId.generate();
            assertThat(id).isNotNull();
            assertThat(id.getValue()).isNotNull();
        }

        @Test
        @DisplayName("generate() produces unique ids")
        void generate_producesUniqueIds() {
            ProfileId id1 = ProfileId.generate();
            ProfileId id2 = ProfileId.generate();
            assertThat(id1).isNotEqualTo(id2);
        }

        @Test
        @DisplayName("throws NullPointerException for null (uses Objects.requireNonNull)")
        void of_throwsNullPointerException_whenNull() {
            assertThatThrownBy(() -> ProfileId.of(null))
                .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("equals: same UUID → equal")
        void equals_sameUUID_isEqual() {
            UUID uuid = UUID.randomUUID();
            assertThat(ProfileId.of(uuid)).isEqualTo(ProfileId.of(uuid));
        }

        @Test
        @DisplayName("equals: different UUID → not equal")
        void equals_differentUUID_isNotEqual() {
            assertThat(ProfileId.of(UUID.randomUUID()))
                .isNotEqualTo(ProfileId.of(UUID.randomUUID()));
        }

        @Test
        @DisplayName("equals: same instance → equal")
        void equals_sameInstance_isEqual() {
            ProfileId id = ProfileId.generate();
            assertThat(id).isEqualTo(id);
        }

        @Test
        @DisplayName("equals: null → not equal")
        void equals_null_isNotEqual() {
            assertThat(ProfileId.generate()).isNotEqualTo(null);
        }

        @Test
        @DisplayName("equals: different type → not equal")
        void equals_differentType_isNotEqual() {
            UUID uuid = UUID.randomUUID();
            assertThat(ProfileId.of(uuid)).isNotEqualTo(uuid);
        }

        @Test
        @DisplayName("hashCode: equal objects have equal hashCode")
        void hashCode_equalObjects_haveSameHashCode() {
            UUID uuid = UUID.randomUUID();
            assertThat(ProfileId.of(uuid).hashCode())
                .isEqualTo(ProfileId.of(uuid).hashCode());
        }

        @Test
        @DisplayName("toString returns UUID string")
        void toString_returnsUUIDString() {
            UUID uuid = UUID.randomUUID();
            assertThat(ProfileId.of(uuid).toString()).isEqualTo(uuid.toString());
        }
    }

    // =========================================================================
    // Cross-cutting: typed exceptions are NOT IllegalArgumentException
    // =========================================================================

    @Nested
    @DisplayName("Typed exception contract (pure-assert)")
    class TypedExceptionContractTests {

        @Test
        @DisplayName("TenantId blank → AssertionException, not IllegalArgumentException")
        void tenantId_blank_throwsAssertionException_notIllegalArgument() {
            assertThatThrownBy(() -> TenantId.of(""))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("PreferenceKey blank → AssertionException, not IllegalArgumentException")
        void preferenceKey_blank_throwsAssertionException_notIllegalArgument() {
            assertThatThrownBy(() -> PreferenceKey.of(""))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("PreferenceId null → MissingMandatoryValueException, not IllegalArgumentException")
        void preferenceId_null_throwsMissingMandatoryValueException_notIllegalArgument() {
            assertThatThrownBy(() -> PreferenceId.of(null))
                .isInstanceOf(MissingMandatoryValueException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("AssertionException carries field name metadata")
        void assertionException_carriesFieldNameMetadata() {
            assertThatThrownBy(() -> TenantId.of(null))
                .isInstanceOf(AssertionException.class)
                .satisfies(ex -> {
                    AssertionException ae = (AssertionException) ex;
                    assertThat(ae.field()).isNotBlank();
                });
        }
    }
}
