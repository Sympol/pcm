package dev.vibeafrika.pcm.profile.infrastructure.persistence.mapper;

import dev.vibeafrika.pcm.profile.domain.model.Handle;
import dev.vibeafrika.pcm.profile.domain.model.Profile;
import dev.vibeafrika.pcm.profile.domain.model.ProfileId;
import dev.vibeafrika.pcm.profile.domain.model.TenantId;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;
import net.jqwik.api.*;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based test for ProfileMapper round-trip translation.
 *
 * Feature: framework-agnostic-domain, Property 13: Mapper Translation Preserves Domain Invariants
 *
 * This test verifies that:
 * 1. domain → JPA → domain round-trip preserves all fields
 * 2. The mapper never loses or corrupts data during translation
 * 3. All domain invariants (id, tenantId, handle, attributes, version, deleted) are preserved
 */
@Label("Feature: framework-agnostic-domain, Property 13: Mapper Translation Preserves Domain Invariants")
class ProfileMapperRoundTripPropertyTest {

    /**
     * Property 13: Round-trip mapping (domain → JPA → domain) preserves all domain invariants.
     */
    @Property(tries = 200)
    @Label("Round-trip domain → JPA → domain preserves all domain invariants")
    void roundTripPreservesAllDomainInvariants(
            @ForAll("validProfiles") Profile original) {

        // When: domain entity is mapped to JPA entity and back
        ProfileJpaEntity jpaEntity = ProfileMapper.toJpaEntity(original);
        Profile reconstituted = ProfileMapper.toDomainEntity(jpaEntity);

        // Then: all domain invariants are preserved
        assertThat(reconstituted.getId()).isEqualTo(original.getId());
        assertThat(reconstituted.getTenantId()).isEqualTo(original.getTenantId());
        assertThat(reconstituted.getHandle()).isEqualTo(original.getHandle());
        assertThat(reconstituted.getAttributes()).isEqualTo(original.getAttributes());
        assertThat(reconstituted.getVersion()).isEqualTo(original.getVersion());
        assertThat(reconstituted.isDeleted()).isEqualTo(original.isDeleted());
        assertThat(reconstituted.getCreatedAt()).isEqualTo(original.getCreatedAt());
        assertThat(reconstituted.getUpdatedAt()).isEqualTo(original.getUpdatedAt());
    }

    /**
     * Property 13: toJpaEntity preserves all primitive fields correctly.
     */
    @Property(tries = 200)
    @Label("toJpaEntity maps all domain fields to JPA entity correctly")
    void toJpaEntityPreservesAllFields(@ForAll("validProfiles") Profile profile) {

        // When: domain entity is mapped to JPA entity
        ProfileJpaEntity jpaEntity = ProfileMapper.toJpaEntity(profile);

        // Then: all fields are correctly mapped
        assertThat(jpaEntity.getId()).isEqualTo(profile.getId().getValue());
        assertThat(jpaEntity.getTenantId()).isEqualTo(profile.getTenantId().getValue());
        assertThat(jpaEntity.getHandle()).isEqualTo(profile.getHandle().getValue());
        assertThat(jpaEntity.getAttributes()).isEqualTo(profile.getAttributes());
        assertThat(jpaEntity.getVersion()).isEqualTo(profile.getVersion());
        assertThat(jpaEntity.isDeleted()).isEqualTo(profile.isDeleted());
    }

    /**
     * Property 13: toDomainEntity reconstitutes domain entity with all invariants intact.
     */
    @Property(tries = 200)
    @Label("toDomainEntity reconstitutes domain entity preserving all invariants")
    void toDomainEntityPreservesAllInvariants(@ForAll("validJpaEntities") ProfileJpaEntity jpaEntity) {

        // When: JPA entity is mapped to domain entity
        Profile domain = ProfileMapper.toDomainEntity(jpaEntity);

        // Then: all domain invariants are preserved
        assertThat(domain.getId().getValue()).isEqualTo(jpaEntity.getId());
        assertThat(domain.getTenantId().getValue()).isEqualTo(jpaEntity.getTenantId());
        assertThat(domain.getHandle().getValue()).isEqualTo(jpaEntity.getHandle());
        assertThat(domain.getAttributes()).isEqualTo(jpaEntity.getAttributes());
        assertThat(domain.getVersion()).isEqualTo(jpaEntity.getVersion());
        assertThat(domain.isDeleted()).isEqualTo(jpaEntity.isDeleted());
    }

    /**
     * Property 13: Mapper returns null for null input without throwing exceptions.
     */
    @Property(tries = 1)
    @Label("Mapper handles null input gracefully")
    void mapperHandlesNullInputGracefully() {
        assertThat(ProfileMapper.toJpaEntity(null)).isNull();
        assertThat(ProfileMapper.toDomainEntity(null)).isNull();
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
            validProfileIds(),
            validTenantIds(),
            validHandles(),
            validAttributes(),
            Arbitraries.longs().between(0L, 100L),
            Arbitraries.of(true, false)
        ).as((id, tenantId, handle, attributes, version, deleted) -> {
            Instant now = Instant.now();
            return Profile.reconstitute(id, tenantId, handle, attributes, now, now, version, deleted);
        });
    }

    @Provide
    Arbitrary<ProfileJpaEntity> validJpaEntities() {
        return Combinators.combine(
            Arbitraries.create(UUID::randomUUID),
            Arbitraries.strings().alpha().numeric().ofMinLength(1).ofMaxLength(100),
            Arbitraries.strings().withCharRange('a', 'z').ofMinLength(3).ofMaxLength(30),
            validAttributes(),
            Arbitraries.longs().between(0L, 100L),
            Arbitraries.of(true, false)
        ).as((id, tenantId, handle, attributes, version, deleted) -> {
            ProfileJpaEntity entity = new ProfileJpaEntity();
            entity.setId(id);
            entity.setTenantId(tenantId);
            entity.setHandle(handle);
            entity.setAttributes(attributes);
            entity.setVersion(version);
            entity.setDeleted(deleted);
            Instant now = Instant.now();
            entity.setCreatedAt(now);
            entity.setUpdatedAt(now);
            return entity;
        });
    }
}
