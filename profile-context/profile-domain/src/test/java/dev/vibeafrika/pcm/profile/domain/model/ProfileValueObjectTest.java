package dev.vibeafrika.pcm.profile.domain.model;

import io.github.sympol.pure.asserts.AssertionException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for Profile domain value objects.
 *
 * Covers:
 * - Handle: valid construction, validation rules (length, pattern), anonymized factory
 * - TenantId: valid construction, null/blank validation
 * - ProfileId: UUID wrapping, generation, equality
 *
 * Tests run WITHOUT Spring context — pure unit tests.
 *
 */
class ProfileValueObjectTest {

    // =========================================================================
    // Handle
    // =========================================================================

    @Nested
    @DisplayName("Handle")
    class HandleTests {

        @Test
        @DisplayName("accepts a valid handle (lowercase alphanumeric)")
        void of_acceptsValidHandle() {
            Handle handle = Handle.of("alice");
            assertThat(handle.getValue()).isEqualTo("alice");
        }

        @Test
        @DisplayName("accepts a handle with underscores")
        void of_acceptsHandleWithUnderscores() {
            Handle handle = Handle.of("alice_bob");
            assertThat(handle.getValue()).isEqualTo("alice_bob");
        }

        @Test
        @DisplayName("accepts exactly 3 characters (minimum boundary)")
        void of_accepts3CharHandle() {
            Handle handle = Handle.of("abc");
            assertThat(handle.getValue()).isEqualTo("abc");
        }

        @Test
        @DisplayName("accepts exactly 30 characters (maximum boundary)")
        void of_accepts30CharHandle() {
            String exactly30 = "a".repeat(30);
            Handle handle = Handle.of(exactly30);
            assertThat(handle.getValue()).isEqualTo(exactly30);
        }

        @Test
        @DisplayName("accepts handle with digits")
        void of_acceptsHandleWithDigits() {
            Handle handle = Handle.of("user123");
            assertThat(handle.getValue()).isEqualTo("user123");
        }

        @Test
        @DisplayName("throws AssertionException for handle shorter than 3 chars")
        void of_throwsAssertionException_whenTooShort() {
            assertThatThrownBy(() -> Handle.of("ab"))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("throws AssertionException for single character handle")
        void of_throwsAssertionException_whenSingleChar() {
            assertThatThrownBy(() -> Handle.of("a"))
                .isInstanceOf(AssertionException.class);
        }

        @Test
        @DisplayName("throws AssertionException for handle longer than 30 chars")
        void of_throwsAssertionException_whenTooLong() {
            String tooLong = "a".repeat(31);
            assertThatThrownBy(() -> Handle.of(tooLong))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("throws AssertionException for uppercase characters")
        void of_throwsAssertionException_whenUppercase() {
            assertThatThrownBy(() -> Handle.of("Alice"))
                .isInstanceOf(AssertionException.class);
        }

        @Test
        @DisplayName("throws AssertionException for special characters")
        void of_throwsAssertionException_whenSpecialChars() {
            assertThatThrownBy(() -> Handle.of("alice@bob"))
                .isInstanceOf(AssertionException.class);
        }

        @Test
        @DisplayName("throws AssertionException for handle with spaces")
        void of_throwsAssertionException_whenContainsSpaces() {
            assertThatThrownBy(() -> Handle.of("alice bob"))
                .isInstanceOf(AssertionException.class);
        }

        @Test
        @DisplayName("throws AssertionException for handle with hyphens")
        void of_throwsAssertionException_whenContainsHyphens() {
            assertThatThrownBy(() -> Handle.of("alice-bob"))
                .isInstanceOf(AssertionException.class);
        }

        @Test
        @DisplayName("throws AssertionException for null handle")
        void of_throwsAssertionException_whenNull() {
            assertThatThrownBy(() -> Handle.of(null))
                .isInstanceOf(AssertionException.class)
                .isNotInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("throws AssertionException for blank handle")
        void of_throwsAssertionException_whenBlank() {
            assertThatThrownBy(() -> Handle.of("   "))
                .isInstanceOf(AssertionException.class);
        }

        @Test
        @DisplayName("throws AssertionException for empty handle")
        void of_throwsAssertionException_whenEmpty() {
            assertThatThrownBy(() -> Handle.of(""))
                .isInstanceOf(AssertionException.class);
        }

        @Test
        @DisplayName("exception carries field name 'handle'")
        void of_exceptionContainsFieldName() {
            assertThatThrownBy(() -> Handle.of(""))
                .isInstanceOf(AssertionException.class)
                .satisfies(ex -> {
                    AssertionException ae = (AssertionException) ex;
                    assertThat(ae.field()).isEqualTo("handle");
                });
        }

        // --- anonymized() ---

        @Test
        @DisplayName("anonymized() returns a non-null handle")
        void anonymized_returnsNonNull() {
            Handle handle = Handle.anonymized();
            assertThat(handle).isNotNull();
            assertThat(handle.getValue()).isNotNull();
        }

        @Test
        @DisplayName("anonymized() handle starts with 'deleted_' prefix")
        void anonymized_startsWithDeletedPrefix() {
            Handle handle = Handle.anonymized();
            assertThat(handle.getValue()).startsWith("deleted_");
        }

        @Test
        @DisplayName("anonymized() isAnonymized() returns true")
        void anonymized_isAnonymized_returnsTrue() {
            Handle handle = Handle.anonymized();
            assertThat(handle.isAnonymized()).isTrue();
        }

        @Test
        @DisplayName("regular handle isAnonymized() returns false")
        void regular_isAnonymized_returnsFalse() {
            Handle handle = Handle.of("alice");
            assertThat(handle.isAnonymized()).isFalse();
        }

        @Test
        @DisplayName("anonymized() produces unique handles each time")
        void anonymized_producesUniqueHandles() {
            Handle h1 = Handle.anonymized();
            Handle h2 = Handle.anonymized();
            assertThat(h1).isNotEqualTo(h2);
        }

        // --- equals / hashCode ---

        @Test
        @DisplayName("equals: same value → equal")
        void equals_sameValue_isEqual() {
            assertThat(Handle.of("alice")).isEqualTo(Handle.of("alice"));
        }

        @Test
        @DisplayName("equals: different value → not equal")
        void equals_differentValue_isNotEqual() {
            assertThat(Handle.of("alice")).isNotEqualTo(Handle.of("bob"));
        }

        @Test
        @DisplayName("equals: same instance → equal")
        void equals_sameInstance_isEqual() {
            Handle h = Handle.of("alice");
            assertThat(h).isEqualTo(h);
        }

        @Test
        @DisplayName("equals: null → not equal")
        void equals_null_isNotEqual() {
            assertThat(Handle.of("alice")).isNotEqualTo(null);
        }

        @Test
        @DisplayName("hashCode: equal objects have equal hashCode")
        void hashCode_equalObjects_haveSameHashCode() {
            assertThat(Handle.of("alice").hashCode())
                .isEqualTo(Handle.of("alice").hashCode());
        }

        @Test
        @DisplayName("toString returns the raw value")
        void toString_returnsRawValue() {
            assertThat(Handle.of("alice").toString()).isEqualTo("alice");
        }
    }

    // =========================================================================
    // TenantId
    // =========================================================================

    @Nested
    @DisplayName("TenantId")
    class TenantIdTests {

        @Test
        @DisplayName("accepts a valid tenant ID")
        void of_acceptsValidTenantId() {
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
        @DisplayName("throws AssertionException for null")
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
        @DisplayName("exception carries field name 'tenantId'")
        void of_exceptionContainsFieldName() {
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
        @DisplayName("throws NullPointerException for null UUID")
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
}
