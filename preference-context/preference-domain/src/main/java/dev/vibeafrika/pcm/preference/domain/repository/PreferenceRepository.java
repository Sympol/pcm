package dev.vibeafrika.pcm.preference.domain.repository;

import dev.vibeafrika.pcm.preference.domain.model.Preference;
import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import dev.vibeafrika.pcm.preference.domain.model.PreferenceKey;
import dev.vibeafrika.pcm.preference.domain.model.ProfileId;
import dev.vibeafrika.pcm.preference.domain.model.TenantId;

import java.util.Optional;

/**
 * Repository interface (port) for Preference aggregate.
 * Defined in domain layer using domain language and types.
 * Implemented in infrastructure layer with framework-specific code.
 * 
 * This interface does NOT extend any framework-specific interfaces
 * (e.g., JpaRepository, CrudRepository) to maintain framework independence.
 */
public interface PreferenceRepository {
    
    /**
     * Save a preference (create or update).
     * 
     * @param preference the preference to save
     * @return the saved preference with updated metadata
     */
    Preference save(Preference preference);
    
    /**
     * Find a preference by its ID.
     * 
     * @param id the preference ID
     * @return an Optional containing the preference if found, empty otherwise
     */
    Optional<Preference> findById(PreferenceId id);
    
    /**
     * Find a preference by a specific setting key.
     * Returns the first preference that contains the given key.
     * 
     * @param key the preference key to search for
     * @return an Optional containing the preference if found, empty otherwise
     */
    Optional<Preference> findByKey(PreferenceKey key);
    
    /**
     * Find a preference by profile ID.
     * 
     * @param profileId the profile ID
     * @return an Optional containing the preference if found, empty otherwise
     */
    Optional<Preference> findByProfileId(ProfileId profileId);
    
    /**
     * Find a preference by profile ID within a specific tenant.
     * 
     * @param profileId the profile ID
     * @param tenantId the tenant ID
     * @return an Optional containing the preference if found, empty otherwise
     */
    Optional<Preference> findByProfileIdAndTenant(ProfileId profileId, TenantId tenantId);
    
    /**
     * Delete a preference (hard delete - use with caution).
     * Prefer using the soft delete method on the Preference entity.
     * 
     * @param preference the preference to delete
     */
    void delete(Preference preference);
}
