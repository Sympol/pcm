package dev.vibeafrika.pcm.preference.domain.model;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests verifying that value objects use pure-assert and throw typed exceptions.
 * 
 * **Validates: Requirements 22.1, 22.2, 22.3, 22.6**
 */
class ValueObjectValidationTest {

    @Test
    void preferenceId_throwsTypedException_whenNull() {
        assertThatThrownBy(() -> PreferenceId.of(null))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("preferenceId");
    }

    @Test
    void tenantId_throwsTypedException_whenNull() {
        assertThatThrownBy(() -> TenantId.of(null))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("tenantId");
    }

    @Test
    void tenantId_throwsTypedException_whenBlank() {
        assertThatThrownBy(() -> TenantId.of("   "))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("tenantId");
    }

    @Test
    void tenantId_throwsTypedException_whenTooLong() {
        String tooLong = "a".repeat(101);
        assertThatThrownBy(() -> TenantId.of(tooLong))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("tenantId")
            .hasMessageContaining("100");
    }

    @Test
    void tenantId_acceptsValidValue() {
        TenantId tenantId = TenantId.of("valid-tenant");
        assertThat(tenantId.getValue()).isEqualTo("valid-tenant");
    }

    @Test
    void preferenceKey_throwsTypedException_whenNull() {
        assertThatThrownBy(() -> PreferenceKey.of(null))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("preferenceKey");
    }

    @Test
    void preferenceKey_throwsTypedException_whenBlank() {
        assertThatThrownBy(() -> PreferenceKey.of(""))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("preferenceKey");
    }

    @Test
    void preferenceKey_throwsTypedException_whenTooLong() {
        String tooLong = "a".repeat(101);
        assertThatThrownBy(() -> PreferenceKey.of(tooLong))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("preferenceKey")
            .hasMessageContaining("100");
    }

    @Test
    void preferenceKey_acceptsValidValue() {
        PreferenceKey key = PreferenceKey.of("theme");
        assertThat(key.getValue()).isEqualTo("theme");
    }

    @Test
    void preferenceId_acceptsValidUUID() {
        UUID uuid = UUID.randomUUID();
        PreferenceId id = PreferenceId.of(uuid);
        assertThat(id.getValue()).isEqualTo(uuid);
    }

    @Test
    void preferenceId_generatesValidId() {
        PreferenceId id = PreferenceId.generate();
        assertThat(id).isNotNull();
        assertThat(id.getValue()).isNotNull();
    }

    @Test
    void exceptionTypes_areNotIllegalArgumentException() {
        // Verify that pure-assert throws typed exceptions, not IllegalArgumentException
        try {
            TenantId.of("");
            fail("Should have thrown an exception");
        } catch (IllegalArgumentException e) {
            fail("Should not throw IllegalArgumentException, but a typed exception from pure-assert");
        } catch (RuntimeException e) {
            // Expected - pure-assert throws typed RuntimeException subclasses
            assertThat(e.getClass().getName()).contains("sympol");
        }
    }
}
