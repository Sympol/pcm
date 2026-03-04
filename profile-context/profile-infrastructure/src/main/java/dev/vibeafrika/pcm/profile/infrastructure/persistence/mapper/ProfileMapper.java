package dev.vibeafrika.pcm.profile.infrastructure.persistence.mapper;

import dev.vibeafrika.pcm.profile.domain.model.*;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;

/**
 * Mapper between domain Profile and JPA ProfileJpaEntity.
 * Handles translation of value objects to/from database primitives.
 * Preserves all domain invariants during translation.
 */
public class ProfileMapper {

    /**
     * Convert domain entity to JPA entity.
     */
    public static ProfileJpaEntity toJpaEntity(Profile profile) {
        if (profile == null) {
            return null;
        }

        ProfileJpaEntity entity = new ProfileJpaEntity();
        entity.setId(profile.getId().getValue());
        entity.setTenantId(profile.getTenantId().getValue());
        entity.setHandle(profile.getHandle().getValue());
        entity.setAttributes(profile.getAttributes());
        entity.setCreatedAt(profile.getCreatedAt());
        entity.setUpdatedAt(profile.getUpdatedAt());
        entity.setVersion(profile.getVersion());
        entity.setDeleted(profile.isDeleted());
        
        return entity;
    }

    /**
     * Convert JPA entity to domain entity.
     * Uses reconstitute factory method to rebuild domain entity from persistence.
     */
    public static Profile toDomainEntity(ProfileJpaEntity entity) {
        if (entity == null) {
            return null;
        }

        return Profile.reconstitute(
            ProfileId.of(entity.getId()),
            TenantId.of(entity.getTenantId()),
            Handle.of(entity.getHandle()),
            entity.getAttributes(),
            entity.getCreatedAt(),
            entity.getUpdatedAt(),
            entity.getVersion(),
            entity.isDeleted()
        );
    }
}
