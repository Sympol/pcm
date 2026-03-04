package dev.vibeafrika.pcm.segment.infrastructure.persistence.repository;

import dev.vibeafrika.pcm.segment.domain.model.*;
import dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository;
import dev.vibeafrika.pcm.segment.infrastructure.persistence.entity.SegmentJpaEntity;
import dev.vibeafrika.pcm.segment.infrastructure.persistence.mapper.SegmentMapper;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Adapter that implements domain SegmentRepository interface
 * using Spring Data JPA repository.
 */
@Component
public class SegmentRepositoryAdapter implements SegmentRepository {

    private final SpringDataSegmentRepository springDataRepository;

    public SegmentRepositoryAdapter(SpringDataSegmentRepository springDataRepository) {
        this.springDataRepository = springDataRepository;
    }

    @Override
    public Segment save(Segment segment) {
        SegmentJpaEntity jpaEntity = SegmentMapper.toJpaEntity(segment);
        SegmentJpaEntity savedEntity = springDataRepository.save(jpaEntity);
        return SegmentMapper.toDomainEntity(savedEntity);
    }

    @Override
    public Optional<Segment> findById(SegmentId id) {
        return springDataRepository.findById(id.getValue())
            .map(SegmentMapper::toDomainEntity);
    }

    @Override
    public Optional<Segment> findByName(SegmentName name, TenantId tenantId) {
        // Note: Current domain model doesn't have 'name' field
        // This method is not applicable to current Segment model (tags/scores per profile)
        // Returning empty for now - this needs domain model clarification
        return Optional.empty();
    }

    @Override
    public List<Segment> findByTenant(TenantId tenantId) {
        return springDataRepository.findByTenantId(tenantId.getValue())
            .stream()
            .map(SegmentMapper::toDomainEntity)
            .collect(Collectors.toList());
    }

    @Override
    public List<Segment> findByProfile(ProfileId profileId, TenantId tenantId) {
        return springDataRepository.findByProfileIdAndTenantId(profileId.getValue(), tenantId.getValue())
            .stream()
            .map(SegmentMapper::toDomainEntity)
            .collect(Collectors.toList());
    }

    @Override
    public boolean existsByName(SegmentName name, TenantId tenantId) {
        // Note: Current domain model doesn't have 'name' field
        // This method is not applicable to current Segment model
        return false;
    }

    @Override
    public void delete(Segment segment) {
        springDataRepository.deleteById(segment.getId().getValue());
    }

    @Override
    public List<Segment> findMatchingSegments(ProfileId profileId, TenantId tenantId) {
        // Note: Current domain model represents segment data per profile (tags/scores)
        // not segment definitions with criteria
        // This method needs clarification - returning segments for profile for now
        return findByProfile(profileId, tenantId);
    }
}
