package dev.vibeafrika.pcm.segment.infrastructure.persistence.mapper;

import dev.vibeafrika.pcm.segment.domain.model.ProfileId;
import dev.vibeafrika.pcm.segment.domain.model.Segment;
import dev.vibeafrika.pcm.segment.domain.model.SegmentId;
import dev.vibeafrika.pcm.segment.domain.model.TenantId;
import dev.vibeafrika.pcm.segment.infrastructure.persistence.entity.SegmentJpaEntity;
import net.jqwik.api.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Property-based test for SegmentMapper round-trip translation.
 *
 * Feature: framework-agnostic-domain, Property 13: Mapper Translation Preserves Domain Invariants
 *
 * This test verifies that:
 * 1. domain → JPA → domain round-trip preserves all fields
 * 2. The mapper never loses or corrupts data during translation
 * 3. All domain invariants (id, tenantId, profileId, tags, scores, lastUpdated) are preserved
 */
@Label("Feature: framework-agnostic-domain, Property 13: Mapper Translation Preserves Domain Invariants")
class SegmentMapperRoundTripPropertyTest {

    /**
     * Property 13: Round-trip mapping (domain → JPA → domain) preserves all domain invariants.
     */
    @Property(tries = 200)
    @Label("Round-trip domain → JPA → domain preserves all domain invariants")
    void roundTripPreservesAllDomainInvariants(@ForAll("validSegments") Segment original) {

        // When: domain entity is mapped to JPA entity and back
        SegmentJpaEntity jpaEntity = SegmentMapper.toJpaEntity(original);
        Segment reconstituted = SegmentMapper.toDomainEntity(jpaEntity);

        // Then: all domain invariants are preserved
        assertThat(reconstituted.getId()).isEqualTo(original.getId());
        assertThat(reconstituted.getTenantId()).isEqualTo(original.getTenantId());
        assertThat(reconstituted.getProfileId()).isEqualTo(original.getProfileId());
        assertThat(reconstituted.getTags()).isEqualTo(original.getTags());
        assertThat(reconstituted.getScores()).isEqualTo(original.getScores());
        assertThat(reconstituted.getLastUpdated()).isEqualTo(original.getLastUpdated());
    }

    /**
     * Property 13: toJpaEntity preserves all primitive fields correctly.
     */
    @Property(tries = 200)
    @Label("toJpaEntity maps all domain fields to JPA entity correctly")
    void toJpaEntityPreservesAllFields(@ForAll("validSegments") Segment segment) {

        // When: domain entity is mapped to JPA entity
        SegmentJpaEntity jpaEntity = SegmentMapper.toJpaEntity(segment);

        // Then: all fields are correctly mapped
        assertThat(jpaEntity.getId()).isEqualTo(segment.getId().getValue());
        assertThat(jpaEntity.getTenantId()).isEqualTo(segment.getTenantId().getValue());
        assertThat(jpaEntity.getProfileId()).isEqualTo(segment.getProfileId().getValue());
        assertThat(jpaEntity.getTags()).isEqualTo(segment.getTags());
        assertThat(jpaEntity.getScores()).isEqualTo(segment.getScores());
        assertThat(jpaEntity.getLastUpdated()).isEqualTo(segment.getLastUpdated());
    }

    /**
     * Property 13: toDomainEntity reconstitutes domain entity with all invariants intact.
     */
    @Property(tries = 200)
    @Label("toDomainEntity reconstitutes domain entity preserving all invariants")
    void toDomainEntityPreservesAllInvariants(@ForAll("validJpaEntities") SegmentJpaEntity jpaEntity) {

        // When: JPA entity is mapped to domain entity
        Segment domain = SegmentMapper.toDomainEntity(jpaEntity);

        // Then: all domain invariants are preserved
        assertThat(domain.getId().getValue()).isEqualTo(jpaEntity.getId());
        assertThat(domain.getTenantId().getValue()).isEqualTo(jpaEntity.getTenantId());
        assertThat(domain.getProfileId().getValue()).isEqualTo(jpaEntity.getProfileId());
        assertThat(domain.getTags()).isEqualTo(jpaEntity.getTags());
        assertThat(domain.getScores()).isEqualTo(jpaEntity.getScores());
        assertThat(domain.getLastUpdated()).isEqualTo(jpaEntity.getLastUpdated());
    }

    // ========== Arbitraries (Generators) ==========

    @Provide
    Arbitrary<SegmentId> validSegmentIds() {
        return Arbitraries.create(SegmentId::generate);
    }

    @Provide
    Arbitrary<TenantId> validTenantIds() {
        return Arbitraries.strings()
            .alpha()
            .ofMinLength(1)
            .ofMaxLength(100)
            .map(TenantId::of);
    }

    @Provide
    Arbitrary<ProfileId> validProfileIds() {
        return Arbitraries.create(ProfileId::generate);
    }

    @Provide
    Arbitrary<Set<String>> validTags() {
        return Arbitraries.strings()
            .alpha()
            .ofMinLength(1)
            .ofMaxLength(50)
            .set()
            .ofMinSize(0)
            .ofMaxSize(5);
    }

    @Provide
    Arbitrary<Map<String, Double>> validScores() {
        return Arbitraries.maps(
            Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(20),
            Arbitraries.doubles().between(0.0, 1.0)
        ).ofMinSize(0).ofMaxSize(5);
    }

    @Provide
    Arbitrary<Segment> validSegments() {
        return Combinators.combine(
            validSegmentIds(),
            validTenantIds(),
            validProfileIds(),
            validTags(),
            validScores()
        ).as((id, tenantId, profileId, tags, scores) -> {
            Instant now = Instant.now();
            return Segment.reconstitute(id, tenantId, profileId, tags, scores, now);
        });
    }

    @Provide
    Arbitrary<SegmentJpaEntity> validJpaEntities() {
        return Combinators.combine(
            Arbitraries.create(UUID::randomUUID),
            Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(100),
            Arbitraries.create(UUID::randomUUID),
            validTags(),
            validScores()
        ).as((id, tenantId, profileId, tags, scores) -> {
            SegmentJpaEntity entity = new SegmentJpaEntity();
            entity.setId(id);
            entity.setTenantId(tenantId);
            entity.setProfileId(profileId);
            entity.setTags(new HashSet<>(tags));
            entity.setScores(new HashMap<>(scores));
            Instant now = Instant.now();
            entity.setLastUpdated(now);
            entity.setCreatedAt(now);
            entity.setUpdatedAt(now);
            return entity;
        });
    }
}
