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
 * Property-based test for ProfileMapper performance.
 *
 * Feature: framework-agnostic-domain, Property 24: Mapper Performance
 *
 * Validates:  mapper translation overhead SHALL be under 1ms per entity.
 *
 * This test verifies that:
 * 1. toJpaEntity conversion completes in under 1ms
 * 2. toDomainEntity conversion completes in under 1ms
 * 3. Performance holds across arbitrary valid inputs (no pathological cases)
 */
@Label("Feature: framework-agnostic-domain, Property 24: Mapper Performance")
class ProfileMapperPerformancePropertyTest {

    private static final long MAX_CONVERSION_NANOS = 1_000_000L; // 1ms in nanoseconds

    /**
     * Property 24: toJpaEntity conversion completes in under 1ms for any valid domain entity.
     * A warmup call is made first to avoid JVM class-loading overhead on the first invocation.
     */
    @Property(tries = 50)
    @Label("toJpaEntity conversion completes in under 1ms")
    void toJpaEntityCompletesUnderOneMilli(@ForAll("validProfiles") Profile profile) {
        // Warmup: discard first call to avoid JVM class-loading overhead
        ProfileMapper.toJpaEntity(profile);

        long start = System.nanoTime();
        ProfileJpaEntity result = ProfileMapper.toJpaEntity(profile);
        long elapsed = System.nanoTime() - start;

        assertThat(result).isNotNull();
        assertThat(elapsed)
            .as("toJpaEntity should complete in under 1ms but took %dns", elapsed)
            .isLessThan(MAX_CONVERSION_NANOS);
    }

    /**
     * Property 24: toDomainEntity conversion completes in under 1ms for any valid JPA entity.
     * A warmup call is made first to avoid JVM class-loading overhead on the first invocation.
     */
    @Property(tries = 50)
    @Label("toDomainEntity conversion completes in under 1ms")
    void toDomainEntityCompletesUnderOneMilli(@ForAll("validJpaEntities") ProfileJpaEntity jpaEntity) {
        // Warmup: discard first call to avoid JVM class-loading overhead
        ProfileMapper.toDomainEntity(jpaEntity);

        long start = System.nanoTime();
        Profile result = ProfileMapper.toDomainEntity(jpaEntity);
        long elapsed = System.nanoTime() - start;

        assertThat(result).isNotNull();
        assertThat(elapsed)
            .as("toDomainEntity should complete in under 1ms but took %dns", elapsed)
            .isLessThan(MAX_CONVERSION_NANOS);
    }

    /**
     * Property 24: Full round-trip (domain → JPA → domain) completes in under 2ms.
     */
    @Property(tries = 50)
    @Label("Full round-trip conversion completes in under 2ms")
    void roundTripCompletesUnderTwoMillis(@ForAll("validProfiles") Profile profile) {
        long start = System.nanoTime();
        ProfileJpaEntity jpaEntity = ProfileMapper.toJpaEntity(profile);
        Profile reconstituted = ProfileMapper.toDomainEntity(jpaEntity);
        long elapsed = System.nanoTime() - start;

        assertThat(reconstituted).isNotNull();
        assertThat(elapsed)
            .as("Round-trip should complete in under 2ms but took %dns", elapsed)
            .isLessThan(MAX_CONVERSION_NANOS * 2);
    }

    // ========== Arbitraries (Generators) ==========

    @Provide
    Arbitrary<Profile> validProfiles() {
        return Combinators.combine(
            Arbitraries.create(ProfileId::generate),
            Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(100).map(TenantId::of),
            Arbitraries.strings().withCharRange('a', 'z').ofMinLength(3).ofMaxLength(30).map(Handle::of),
            Arbitraries.maps(
                Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(20),
                Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(50).map(s -> (Object) s)
            ).ofMinSize(0).ofMaxSize(5),
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
            Arbitraries.maps(
                Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(20),
                Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(50).map(s -> (Object) s)
            ).ofMinSize(0).ofMaxSize(5),
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
