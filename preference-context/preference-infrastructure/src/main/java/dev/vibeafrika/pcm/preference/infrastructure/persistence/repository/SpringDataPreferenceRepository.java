package dev.vibeafrika.pcm.preference.infrastructure.persistence.repository;

import dev.vibeafrika.pcm.preference.infrastructure.persistence.entity.PreferenceJpaEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository for PreferenceJpaEntity.
 * Provides database access using Spring Data abstractions.
 */
@Repository
public interface SpringDataPreferenceRepository extends JpaRepository<PreferenceJpaEntity, UUID> {

    /**
     * Find preference by profile ID.
     */
    Optional<PreferenceJpaEntity> findByProfileId(UUID profileId);

    /**
     * Find preference by tenant ID and profile ID.
     */
    Optional<PreferenceJpaEntity> findByTenantIdAndProfileId(String tenantId, UUID profileId);

    /**
     * Find all preferences for a tenant.
     */
    List<PreferenceJpaEntity> findByTenantId(String tenantId);

    /**
     * Find all active (non-deleted) preferences for a tenant.
     */
    @Query("SELECT p FROM PreferenceJpaEntity p WHERE p.tenantId = :tenantId AND p.deleted = false")
    List<PreferenceJpaEntity> findActiveByTenantId(@Param("tenantId") String tenantId);

    /**
     * Check if preference exists for profile.
     */
    boolean existsByProfileId(UUID profileId);
}
