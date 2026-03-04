package dev.vibeafrika.pcm.infrastructure.encryption.repository;

import dev.vibeafrika.pcm.infrastructure.encryption.entity.IVCounterStateEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository for IV counter state persistence.
 * 
 * Provides database access for storing and retrieving counter state
 * to ensure IV uniqueness across application restarts.
 */
@Repository
public interface IVCounterStateRepository extends JpaRepository<IVCounterStateEntity, Long> {
    
    /**
     * Finds the counter state for a specific DEK.
     * 
     * @param dekId The DEK identifier
     * @return Optional containing the state if found
     */
    Optional<IVCounterStateEntity> findByDekId(UUID dekId);
    
    /**
     * Deletes the counter state for a specific DEK.
     * 
     * @param dekId The DEK identifier
     */
    void deleteByDekId(UUID dekId);
}
