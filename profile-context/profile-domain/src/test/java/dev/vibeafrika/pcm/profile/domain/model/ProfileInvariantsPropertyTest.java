package dev.vibeafrika.pcm.profile.domain.model;

import dev.vibeafrika.pcm.profile.domain.exception.ProfileDeletedException;
import dev.vibeafrika.pcm.profile.domain.exception.ProfileDomainException;
import io.github.sympol.pure.asserts.AssertionException;
import net.jqwik.api.*;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Property-based test for Profile domain entity invariants.
 *
 *
 * Feature: framework-agnostic-domain, Property 3: Domain Entities Enforce Invariants
 *
 * This test verifies that:
 * 1. Profile.create() enforces null checks and throws domain exceptions
 * 2. Profile.updateAttributes() throws ProfileDeletedException when profile is deleted
 * 3. Profile.erase() makes the profile deleted and clears attributes
 * 4. Handle.of() throws a typed exception for invalid handles
 * 5. Valid Profile creation always succeeds with valid inputs
 */
@Label("Feature: framework-agnostic-domain, Property 3: Domain Entities Enforce Invariants")
class ProfileInvariantsPropertyTest {

    /**
     * Property: Creating a profile with null tenantId throws a domain/typed exception.
     */
    @Property(tries = 100)
    @Label("Profile creation enforces non-null tenantId invariant")
    void profileCreationEnforcesNonNullTenantId(@ForAll("validHandles") Handle handle) {
        assertThatThrownBy(() -> Profile.create(null, handle, Map.of()))
            .isNotInstanceOf(IllegalArgumentException.class)
            .isInstanceOf(RuntimeException.class);
    }

    /**
     * Property: Creating a profile with null handle throws a domain/typed exception.
     */
    @Property(tries = 100)
    @Label("Profile creation enforces non-null handle invariant")
    void profileCreationEnforcesNonNullHandle(@ForAll("validTenantIds") TenantId tenantId) {
        assertThatThrownBy(() -> Profile.create(tenantId, null, Map.of()))
            .isNotInstanceOf(IllegalArgumentException.class)
            .isInstanceOf(RuntimeException.class);
    }

    /**
     * Property: Updating attributes on a deleted profile throws ProfileDeletedException.
     */
    @Property(tries = 100)
    @Label("Deleted profiles cannot have attributes updated")
    void deletedProfilesCannotBeUpdated(
            @ForAll("validProfiles") Profile profile,
            @ForAll("validAttributes") Map<String, Object> newAttributes) {

        // Given: A deleted profile
        profile.erase();

        // When/Then: Attempting to update throws ProfileDeletedException (domain exception)
        assertThatThrownBy(() -> profile.updateAttributes(newAttributes))
            .isInstanceOf(ProfileDeletedException.class)
            .isInstanceOf(ProfileDomainException.class)
            .isNotInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Cannot update deleted profile");
    }

    /**
     * Property: Erasing a profile marks it as deleted and clears attributes.
     */
    @Property(tries = 100)
    @Label("Erasing a profile marks it deleted and clears attributes")
    void erasingProfileMarksDeletedAndClearsAttributes(
            @ForAll("validTenantIds") TenantId tenantId,
            @ForAll("validHandles") Handle handle,
            @ForAll("validAttributes") Map<String, Object> attributes) {

        // Given: An active profile with attributes
        Profile profile = Profile.create(tenantId, handle, attributes);
        assertThat(profile.isDeleted()).isFalse();

        // When: Profile is erased
        profile.erase();

        // Then: Profile is deleted and attributes are cleared
        assertThat(profile.isDeleted()).isTrue();
        assertThat(profile.isActive()).isFalse();
        assertThat(profile.getAttributes()).isEmpty();
        assertThat(profile.getHandle().isAnonymized()).isTrue();
    }

    /**
     * Property: Handle.of() throws a typed exception (AssertionException) for handles that are too short.
     */
    @Property(tries = 100)
    @Label("Handle.of() throws typed exception for handles shorter than 3 characters")
    void handleOfThrowsTypedExceptionForTooShortHandles(@ForAll("tooShortHandleStrings") String shortHandle) {
        assertThatThrownBy(() -> Handle.of(shortHandle))
            .isInstanceOf(AssertionException.class)
            .isNotInstanceOf(IllegalArgumentException.class);
    }

    /**
     * Property: Handle.of() throws a typed exception (AssertionException) for handles that are too long.
     */
    @Property(tries = 100)
    @Label("Handle.of() throws typed exception for handles longer than 30 characters")
    void handleOfThrowsTypedExceptionForTooLongHandles(@ForAll("tooLongHandleStrings") String longHandle) {
        assertThatThrownBy(() -> Handle.of(longHandle))
            .isInstanceOf(AssertionException.class)
            .isNotInstanceOf(IllegalArgumentException.class);
    }

    /**
     * Property: Handle.of() throws a typed exception for handles with invalid characters.
     */
    @Property(tries = 100)
    @Label("Handle.of() throws typed exception for handles with invalid characters")
    void handleOfThrowsTypedExceptionForInvalidCharacters(@ForAll("invalidCharHandleStrings") String invalidHandle) {
        assertThatThrownBy(() -> Handle.of(invalidHandle))
            .isInstanceOf(AssertionException.class)
            .isNotInstanceOf(IllegalArgumentException.class);
    }

    /**
     * Property: Valid Profile creation always succeeds with valid inputs.
     */
    @Property(tries = 100)
    @Label("Valid Profile creation always succeeds with valid inputs")
    void validProfileCreationAlwaysSucceeds(
            @ForAll("validTenantIds") TenantId tenantId,
            @ForAll("validHandles") Handle handle,
            @ForAll("validAttributes") Map<String, Object> attributes) {

        // When: Profile is created with valid inputs
        Profile profile = Profile.create(tenantId, handle, attributes);

        // Then: Profile is in a consistent initial state
        assertThat(profile.getId()).isNotNull();
        assertThat(profile.getTenantId()).isEqualTo(tenantId);
        assertThat(profile.getHandle()).isEqualTo(handle);
        assertThat(profile.isDeleted()).isFalse();
        assertThat(profile.isActive()).isTrue();
        assertThat(profile.getVersion()).isEqualTo(0L);
        assertThat(profile.getCreatedAt()).isNotNull();
        assertThat(profile.getUpdatedAt()).isNotNull();
    }

    /**
     * Property: Reconstituted profiles maintain all invariants.
     */
    @Property(tries = 100)
    @Label("Reconstituted profiles maintain domain invariants")
    void reconstituedProfilesMaintainInvariants(
            @ForAll("validProfileIds") ProfileId id,
            @ForAll("validTenantIds") TenantId tenantId,
            @ForAll("validHandles") Handle handle,
            @ForAll("validAttributes") Map<String, Object> attributes,
            @ForAll boolean deleted) {

        Instant now = Instant.now();
        Profile profile = Profile.reconstitute(id, tenantId, handle, attributes, now, now, 1L, deleted);

        assertThat(profile.getId()).isEqualTo(id);
        assertThat(profile.getTenantId()).isEqualTo(tenantId);
        assertThat(profile.isDeleted()).isEqualTo(deleted);
        assertThat(profile.isActive()).isEqualTo(!deleted);
    }

    // ========== Arbitraries (Generators) ==========

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
    Arbitrary<Handle> validHandles() {
        return Arbitraries.strings()
            .withCharRange('a', 'z')
            .ofMinLength(3)
            .ofMaxLength(30)
            .map(Handle::of);
    }

    @Provide
    Arbitrary<ProfileId> validProfileIds() {
        return Arbitraries.create(ProfileId::generate);
    }

    @Provide
    Arbitrary<Map<String, Object>> validAttributes() {
        return Arbitraries.maps(
            Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(20),
            Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(50).map(s -> (Object) s)
        ).ofMinSize(0).ofMaxSize(5);
    }

    @Provide
    Arbitrary<Profile> validProfiles() {
        return Combinators.combine(
            validTenantIds(),
            validHandles(),
            validAttributes()
        ).as(Profile::create);
    }

    @Provide
    Arbitrary<String> tooShortHandleStrings() {
        // 1 or 2 lowercase alphanumeric characters (valid chars but too short)
        return Arbitraries.strings()
            .withCharRange('a', 'z')
            .ofMinLength(1)
            .ofMaxLength(2);
    }

    @Provide
    Arbitrary<String> tooLongHandleStrings() {
        // 31+ lowercase alphanumeric characters (valid chars but too long)
        return Arbitraries.strings()
            .withCharRange('a', 'z')
            .ofMinLength(31)
            .ofMaxLength(50);
    }

    @Provide
    Arbitrary<String> invalidCharHandleStrings() {
        // Handles with uppercase letters (invalid characters, valid length)
        return Arbitraries.strings()
            .withCharRange('A', 'Z')
            .ofMinLength(3)
            .ofMaxLength(30);
    }
}
