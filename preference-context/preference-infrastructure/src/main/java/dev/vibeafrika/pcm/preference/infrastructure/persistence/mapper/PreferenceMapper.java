package dev.vibeafrika.pcm.preference.infrastructure.persistence.mapper;

import dev.vibeafrika.pcm.preference.domain.model.*;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.entity.PreferenceJpaEntity;

/**
 * Mapper between domain Preference and JPA PreferenceJpaEntity.
 * Handles translation of value objects to/from database primitives.
 * Preserves all domain invariants during translation.
 */
public class PreferenceMapper {

    /**
     * Convert domain entity to JPA entity.
     * 
     * @param preference the domain preference
     * @return the JPA entity
     */
    public static PreferenceJpaEntity toJpaEntity(Preference preference) {
        if (preference == null) {
            return null;
        }

        PreferenceJpaEntity entity = new PreferenceJpaEntity();
        entity.setId(preference.getId().getValue());
        entity.setTenantId(preference.getTenantId().getValue());
        entity.setProfileId(preference.getProfileId().getValue());
        entity.setSettings(preference.getSettings());
        entity.setLastUpdated(preference.getLastUpdated());
        entity.setDeleted(preference.isDeleted());
        
        return entity;
    }

    /**
     * Convert JPA entity to domain entity.
     * Uses reconstitute factory method to rebuild domain entity from persistence.
     * 
     * @param entity the JPA entity
     * @return the domain preference
     */
    public static Preference toDomainEntity(PreferenceJpaEntity entity) {
        if (entity == null) {
            return null;
        }

        return Preference.reconstitute(
            PreferenceId.of(entity.getId()),
            TenantId.of(entity.getTenantId()),
            ProfileId.of(entity.getProfileId()),
            entity.getSettings(),
            entity.getLastUpdated(),
            entity.isDeleted()
        );
    }
}
