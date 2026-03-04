package dev.vibeafrika.pcm.segment.infrastructure.persistence.repository;

import dev.vibeafrika.pcm.segment.infrastructure.persistence.entity.SegmentJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * Spring Data JPA repository for SegmentJpaEntity.
 */
@Repository
public interface SpringDataSegmentRepository extends JpaRepository<SegmentJpaEntity, UUID> {

    List<SegmentJpaEntity> findByTenantId(String tenantId);
    
    List<SegmentJpaEntity> findByProfileIdAndTenantId(UUID profileId, String tenantId);
}
