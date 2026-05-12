package dev.vibeafrika.pcm.consent.infrastructure.persistence.repository;

import dev.vibeafrika.pcm.consent.infrastructure.persistence.entity.ConsentJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface SpringDataConsentRepository extends JpaRepository<ConsentJpaEntity, UUID> {

    List<ConsentJpaEntity> findByProfileId(UUID profileId);
    
    @Query("SELECT c FROM ConsentJpaEntity c WHERE c.profileId = :profileId AND c.status = 'GRANTED'")
    List<ConsentJpaEntity> findActiveConsentsByProfileId(@Param("profileId") UUID profileId);
    
    List<ConsentJpaEntity> findByTenantId(String tenantId);
    
    List<ConsentJpaEntity> findByPurpose(String purpose);
}
