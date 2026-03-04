package dev.vibeafrika.pcm.segment.infrastructure.persistence.mapper;

import dev.vibeafrika.pcm.segment.domain.model.*;
import dev.vibeafrika.pcm.segment.infrastructure.persistence.entity.SegmentJpaEntity;

/**
 * Mapper between Segment domain entity and SegmentJpaEntity.
 * Handles translation between domain types and persistence types.
 */
public final class SegmentMapper {

    private SegmentMapper() {
        // Utility class
    }

    /**
     * Convert domain Segment to JPA entity.
     */
    public static SegmentJpaEntity toJpaEntity(Segment segment) {
        SegmentJpaEntity jpaEntity = new SegmentJpaEntity();
        jpaEntity.setId(segment.getId().getValue());
        jpaEntity.setTenantId(segment.getTenantId().getValue());
        jpaEntity.setProfileId(segment.getProfileId().getValue());
        jpaEntity.setTags(segment.getTags());
        jpaEntity.setScores(segment.getScores());
        jpaEntity.setLastUpdated(segment.getLastUpdated());
        return jpaEntity;
    }

    /**
     * Convert JPA entity to domain Segment.
     */
    public static Segment toDomainEntity(SegmentJpaEntity jpaEntity) {
        return Segment.reconstitute(
            SegmentId.of(jpaEntity.getId()),
            TenantId.of(jpaEntity.getTenantId()),
            ProfileId.of(jpaEntity.getProfileId()),
            jpaEntity.getTags(),
            jpaEntity.getScores(),
            jpaEntity.getLastUpdated()
        );
    }
}
