package dev.vibeafrika.pcm.profile.infrastructure.persistence.repository;

import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository for ProfileJpaEntity.
 */
@Repository
public interface SpringDataProfileRepository extends JpaRepository<ProfileJpaEntity, UUID> {

    Optional<ProfileJpaEntity> findByHandleAndTenantId(String handle, String tenantId);
    
    Optional<ProfileJpaEntity> findByIdAndTenantId(UUID id, String tenantId);
    
    boolean existsByHandleAndTenantId(String handle, String tenantId);
}
