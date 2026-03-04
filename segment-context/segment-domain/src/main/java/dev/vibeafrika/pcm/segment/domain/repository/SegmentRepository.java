package dev.vibeafrika.pcm.segment.domain.repository;

import dev.vibeafrika.pcm.segment.domain.model.*;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface (port) for Segment aggregate.
 * Defined in domain layer using pure domain types and domain language.
 * Implemented in infrastructure layer (adapter).
 * 
 * This interface does NOT extend Spring Data interfaces (JpaRepository, CrudRepository)
 * to maintain framework independence.
 */
public interface SegmentRepository {
    
    /**
     * Save a segment (create or update).
     * @param segment the segment to save
     * @return the saved segment with updated metadata
     */
    Segment save(Segment segment);
    
    /**
     * Find a segment by its ID.
     * @param id the segment identifier
     * @return an Optional containing the segment if found, empty otherwise
     */
    Optional<Segment> findById(SegmentId id);
    
    /**
     * Find a segment by name within a specific tenant.
     * @param name the segment name
     * @param tenantId the tenant identifier
     * @return an Optional containing the segment if found, empty otherwise
     */
    Optional<Segment> findByName(SegmentName name, TenantId tenantId);
    
    /**
     * Find all segments for a specific tenant.
     * @param tenantId the tenant identifier
     * @return list of segments belonging to the tenant
     */
    List<Segment> findByTenant(TenantId tenantId);
    
    /**
     * Find all segments associated with a specific profile.
     * @param profileId the profile identifier
     * @param tenantId the tenant identifier
     * @return list of segments for the profile
     */
    List<Segment> findByProfile(ProfileId profileId, TenantId tenantId);
    
    /**
     * Check if a segment with the given name exists within a tenant.
     * @param name the segment name
     * @param tenantId the tenant identifier
     * @return true if a segment with this name exists, false otherwise
     */
    boolean existsByName(SegmentName name, TenantId tenantId);
    
    /**
     * Delete a segment.
     * @param segment the segment to delete
     */
    void delete(Segment segment);
    
    /**
     * Find all segments that match the given profile based on segment criteria.
     * This is a business logic operation that evaluates segment membership.
     * @param profileId the profile identifier
     * @param tenantId the tenant identifier
     * @return list of matching segments
     */
    List<Segment> findMatchingSegments(ProfileId profileId, TenantId tenantId);
}
