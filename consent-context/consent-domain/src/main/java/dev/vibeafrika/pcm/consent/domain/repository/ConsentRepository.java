package dev.vibeafrika.pcm.consent.domain.repository;

import dev.vibeafrika.pcm.consent.domain.model.*;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface (port) for Consent aggregate.
 * Defined in domain layer, implemented in infrastructure layer.
 * Uses domain types and domain language.
 */
public interface ConsentRepository {
    
    /**
     * Save a consent (create or update).
     * @return the saved consent with updated version
     */
    Consent save(Consent consent);
    
    /**
     * Find a consent by its ID.
     */
    Optional<Consent> findById(ConsentId id);
    
    /**
     * Find all consents for a profile.
     */
    List<Consent> findByProfile(ProfileId profileId);
    
    /**
     * Find active consents for a profile.
     */
    List<Consent> findActiveConsents(ProfileId profileId);
    
    /**
     * Find consents by purpose.
     */
    List<Consent> findByPurpose(ConsentPurpose purpose);
    
    /**
     * Get consent history for a profile (all events).
     */
    List<Consent> getConsentHistory(ProfileId profileId);
    
    /**
     * Delete a consent (hard delete - use with caution).
     */
    void delete(Consent consent);
}
