package dev.vibeafrika.pcm.preference.domain.model;

import dev.vibeafrika.pcm.preference.domain.exception.PreferenceDeletedException;
import dev.vibeafrika.pcm.preference.domain.exception.PreferenceValidationException;
import net.jqwik.api.*;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Property-based test for Preference domain entity invariants.
 * 
 * 
 * Feature: framework-agnostic-domain, Property 3: Domain Entities Enforce Invariants
 * 
 * This test verifies that:
 * 1. Domain entities throw domain exceptions when invariants are violated
 * 2. Domain entities enforce validation rules in constructors and methods
 * 3. Domain entities maintain consistency throughout their lifecycle
 */
@Label("Feature: framework-agnostic-domain, Property 3: Domain Entities Enforce Invariants")
class PreferenceInvariantsPropertyTest {

    /**
     * Property: Creating a preference with null tenant ID throws domain exception.
     */
    @Property(tries = 100)
    @Label("Preference creation enforces non-null tenant ID invariant")
    void preferenceCreationEnforcesNonNullTenantId(@ForAll("validProfileIds") ProfileId profileId) {
        assertThatThrownBy(() -> Preference.create(null, profileId))
            .isInstanceOf(PreferenceValidationException.class)
            .hasMessageContaining("Tenant ID cannot be null");
    }

    /**
     * Property: Creating a preference with null profile ID throws domain exception.
     */
    @Property(tries = 100)
    @Label("Preference creation enforces non-null profile ID invariant")
    void preferenceCreationEnforcesNonNullProfileId(@ForAll("validTenantIds") TenantId tenantId) {
        assertThatThrownBy(() -> Preference.create(tenantId, null))
            .isInstanceOf(PreferenceValidationException.class)
            .hasMessageContaining("Profile ID cannot be null");
    }

    /**
     * Property: Updating settings on a deleted preference throws domain exception.
     */
    @Property(tries = 100)
    @Label("Deleted preferences cannot be updated")
    void deletedPreferencesCannotBeUpdated(
            @ForAll("validPreferences") Preference preference,
            @ForAll("validSettings") Map<String, String> newSettings) {
        
        // Given: A deleted preference
        preference.delete();
        
        // When/Then: Attempting to update throws domain exception
        assertThatThrownBy(() -> preference.updateSettings(newSettings))
            .isInstanceOf(PreferenceDeletedException.class)
            .hasMessageContaining("Cannot update deleted preference");
    }

    /**
     * Property: Setting a single setting on a deleted preference throws domain exception.
     */
    @Property(tries = 100)
    @Label("Deleted preferences cannot have individual settings updated")
    void deletedPreferencesCannotHaveSettingsSet(
            @ForAll("validPreferences") Preference preference,
            @ForAll("validPreferenceKeys") PreferenceKey key,
            @ForAll String value) {
        
        // Given: A deleted preference
        preference.delete();
        
        // When/Then: Attempting to set a setting throws domain exception
        assertThatThrownBy(() -> preference.setSetting(key, value))
            .isInstanceOf(PreferenceDeletedException.class)
            .hasMessageContaining("Cannot update deleted preference");
    }

    /**
     * Property: Removing a setting from a deleted preference throws domain exception.
     */
    @Property(tries = 100)
    @Label("Deleted preferences cannot have settings removed")
    void deletedPreferencesCannotHaveSettingsRemoved(
            @ForAll("validPreferences") Preference preference,
            @ForAll("validPreferenceKeys") PreferenceKey key) {
        
        // Given: A deleted preference
        preference.delete();
        
        // When/Then: Attempting to remove a setting throws domain exception
        assertThatThrownBy(() -> preference.removeSetting(key))
            .isInstanceOf(PreferenceDeletedException.class)
            .hasMessageContaining("Cannot update deleted preference");
    }

    /**
     * Property: Updating settings with null map throws domain exception.
     */
    @Property(tries = 100)
    @Label("Preference update enforces non-null settings invariant")
    void preferenceUpdateEnforcesNonNullSettings(@ForAll("validPreferences") Preference preference) {
        assertThatThrownBy(() -> preference.updateSettings(null))
            .isInstanceOf(PreferenceValidationException.class)
            .hasMessageContaining("Settings cannot be null or empty");
    }

    /**
     * Property: Updating settings with empty map throws domain exception.
     */
    @Property(tries = 100)
    @Label("Preference update enforces non-empty settings invariant")
    void preferenceUpdateEnforcesNonEmptySettings(@ForAll("validPreferences") Preference preference) {
        assertThatThrownBy(() -> preference.updateSettings(Map.of()))
            .isInstanceOf(PreferenceValidationException.class)
            .hasMessageContaining("Settings cannot be null or empty");
    }

    /**
     * Property: Setting a null key throws domain exception.
     */
    @Property(tries = 100)
    @Label("Setting individual preference enforces non-null key invariant")
    void settingPreferenceEnforcesNonNullKey(
            @ForAll("validPreferences") Preference preference,
            @ForAll String value) {
        
        assertThatThrownBy(() -> preference.setSetting(null, value))
            .isInstanceOf(PreferenceValidationException.class)
            .hasMessageContaining("Setting key cannot be null");
    }

    /**
     * Property: Setting a null value throws domain exception.
     */
    @Property(tries = 100)
    @Label("Setting individual preference enforces non-null value invariant")
    void settingPreferenceEnforcesNonNullValue(
            @ForAll("validPreferences") Preference preference,
            @ForAll("validPreferenceKeys") PreferenceKey key) {
        
        assertThatThrownBy(() -> preference.setSetting(key, null))
            .isInstanceOf(PreferenceValidationException.class)
            .hasMessageContaining("Setting value cannot be null");
    }

    /**
     * Property: Getting a setting with null key throws domain exception.
     */
    @Property(tries = 100)
    @Label("Getting preference setting enforces non-null key invariant")
    void gettingPreferenceEnforcesNonNullKey(@ForAll("validPreferences") Preference preference) {
        assertThatThrownBy(() -> preference.getSetting(null))
            .isInstanceOf(PreferenceValidationException.class)
            .hasMessageContaining("Setting key cannot be null");
    }

    /**
     * Property: Removing a setting with null key throws domain exception.
     */
    @Property(tries = 100)
    @Label("Removing preference setting enforces non-null key invariant")
    void removingPreferenceEnforcesNonNullKey(@ForAll("validPreferences") Preference preference) {
        assertThatThrownBy(() -> preference.removeSetting(null))
            .isInstanceOf(PreferenceValidationException.class)
            .hasMessageContaining("Setting key cannot be null");
    }

    /**
     * Property: Updating settings with invalid keys throws domain exception.
     */
    @Property(tries = 100)
    @Label("Preference update validates all setting keys")
    void preferenceUpdateValidatesSettingKeys(
            @ForAll("validPreferences") Preference preference,
            @ForAll("invalidSettingKeys") String invalidKey) {
        
        Map<String, String> invalidSettings = Map.of(invalidKey, "value");
        
        assertThatThrownBy(() -> preference.updateSettings(invalidSettings))
            .isInstanceOf(PreferenceValidationException.class)
            .hasMessageContaining("Setting key");
    }

    /**
     * Property: Preference maintains consistency after valid operations.
     */
    @Property(tries = 100)
    @Label("Preference maintains consistency throughout lifecycle")
    void preferenceMaintainsConsistency(
            @ForAll("validTenantIds") TenantId tenantId,
            @ForAll("validProfileIds") ProfileId profileId,
            @ForAll("validSettings") Map<String, String> initialSettings,
            @ForAll("validSettings") Map<String, String> updatedSettings) {
        
        // Given: A new preference
        Preference preference = Preference.create(tenantId, profileId, initialSettings);
        
        // Then: Initial state is consistent
        assertThat(preference.getId()).isNotNull();
        assertThat(preference.getTenantId()).isEqualTo(tenantId);
        assertThat(preference.getProfileId()).isEqualTo(profileId);
        assertThat(preference.isActive()).isTrue();
        assertThat(preference.isDeleted()).isFalse();
        assertThat(preference.getLastUpdated()).isNotNull();
        
        // When: Settings are updated
        Instant beforeUpdate = preference.getLastUpdated();
        preference.updateSettings(updatedSettings);
        
        // Then: State remains consistent
        assertThat(preference.getId()).isNotNull();
        assertThat(preference.getTenantId()).isEqualTo(tenantId);
        assertThat(preference.getProfileId()).isEqualTo(profileId);
        assertThat(preference.isActive()).isTrue();
        assertThat(preference.getLastUpdated()).isAfterOrEqualTo(beforeUpdate);
        
        // When: Preference is deleted
        preference.delete();
        
        // Then: Deleted state is consistent
        assertThat(preference.isDeleted()).isTrue();
        assertThat(preference.isActive()).isFalse();
    }

    /**
     * Property: Reconstituted preferences maintain invariants.
     */
    @Property(tries = 100)
    @Label("Reconstituted preferences maintain domain invariants")
    void reconstituedPreferencesMaintainInvariants(
            @ForAll("validPreferenceIds") PreferenceId id,
            @ForAll("validTenantIds") TenantId tenantId,
            @ForAll("validProfileIds") ProfileId profileId,
            @ForAll("validSettings") Map<String, String> settings,
            @ForAll boolean deleted) {
        
        // When: Preference is reconstituted from persistence
        Instant lastUpdated = Instant.now();
        Preference preference = Preference.reconstitute(id, tenantId, profileId, settings, lastUpdated, deleted);
        
        // Then: All invariants are maintained
        assertThat(preference.getId()).isEqualTo(id);
        assertThat(preference.getTenantId()).isEqualTo(tenantId);
        assertThat(preference.getProfileId()).isEqualTo(profileId);
        assertThat(preference.getSettings()).isEqualTo(settings);
        assertThat(preference.getLastUpdated()).isEqualTo(lastUpdated);
        assertThat(preference.isDeleted()).isEqualTo(deleted);
        assertThat(preference.isActive()).isEqualTo(!deleted);
    }

    // ========== Arbitraries (Generators) ==========

    @Provide
    Arbitrary<PreferenceId> validPreferenceIds() {
        return Arbitraries.create(() -> PreferenceId.generate());
    }

    @Provide
    Arbitrary<TenantId> validTenantIds() {
        return Arbitraries.strings()
            .alpha()
            .numeric()
            .ofMinLength(1)
            .ofMaxLength(100)
            .map(TenantId::of);
    }

    @Provide
    Arbitrary<ProfileId> validProfileIds() {
        return Arbitraries.create(() -> ProfileId.generate());
    }

    @Provide
    Arbitrary<PreferenceKey> validPreferenceKeys() {
        return Arbitraries.strings()
            .alpha()
            .numeric()
            .ofMinLength(1)
            .ofMaxLength(100)
            .map(PreferenceKey::of);
    }

    @Provide
    Arbitrary<Map<String, String>> validSettings() {
        return Arbitraries.maps(
            Arbitraries.strings().alpha().numeric().ofMinLength(1).ofMaxLength(50),
            Arbitraries.strings().alpha().numeric().ofMinLength(1).ofMaxLength(200)
        ).ofMinSize(1).ofMaxSize(10);
    }

    @Provide
    Arbitrary<Preference> validPreferences() {
        return Combinators.combine(
            validTenantIds(),
            validProfileIds(),
            validSettings()
        ).as(Preference::create);
    }

    @Provide
    Arbitrary<String> invalidSettingKeys() {
        return Arbitraries.oneOf(
            // Blank keys
            Arbitraries.just(""),
            Arbitraries.just("   "),
            // Keys exceeding max length
            Arbitraries.strings().alpha().ofMinLength(101).ofMaxLength(200)
        );
    }
}
