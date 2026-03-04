package dev.vibeafrika.pcm.profile.domain.repository;

import dev.vibeafrika.pcm.profile.domain.model.Handle;
import dev.vibeafrika.pcm.profile.domain.model.Profile;
import dev.vibeafrika.pcm.profile.domain.model.ProfileId;
import dev.vibeafrika.pcm.profile.domain.model.TenantId;

import java.util.Optional;

/**
 * Repository interface (port) for Profile aggregate.
 * Defined in domain layer, implemented in infrastructure layer.
 * 
 * Uses domain types and domain language, not database terminology.
 * Does not extend framework-specific interfaces.
 */
public interface ProfileRepository {
    
    /**
     * Save a profile (create or update).
     * 
     * @param profile The profile to save
     * @return The saved profile with updated version
     */
    Profile save(Profile profile);
    
    /**
     * Find a profile by its ID.
     * 
     * @param id The profile ID
     * @return Optional containing the profile if found
     */
    Optional<Profile> findById(ProfileId id);
    
    /**
     * Find a profile by handle within a specific tenant.
     * 
     * @param handle The handle to search for
     * @param tenantId The tenant ID
     * @return Optional containing the profile if found
     */
    Optional<Profile> findByHandle(Handle handle, TenantId tenantId);
    
    /**
     * Find a profile by ID within a specific tenant.
     * Ensures tenant isolation.
     * 
     * @param id The profile ID
     * @param tenantId The tenant ID
     * @return Optional containing the profile if found
     */
    Optional<Profile> findByIdAndTenant(ProfileId id, TenantId tenantId);
    
    /**
     * Check if a handle is already taken within a tenant.
     * 
     * @param handle The handle to check
     * @param tenantId The tenant ID
     * @return true if the handle exists, false otherwise
     */
    boolean existsByHandle(Handle handle, TenantId tenantId);
    
    /**
     * Delete a profile (hard delete - use with caution).
     * For GDPR compliance, prefer using Profile.erase() for soft delete.
     * 
     * @param profile The profile to delete
     */
    void delete(Profile profile);
}
