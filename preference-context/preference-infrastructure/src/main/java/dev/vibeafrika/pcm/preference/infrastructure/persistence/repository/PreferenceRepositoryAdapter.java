package dev.vibeafrika.pcm.preference.infrastructure.persistence.repository;

import dev.vibeafrika.pcm.preference.domain.model.*;
import dev.vibeafrika.pcm.preference.domain.repository.PreferenceRepository;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.entity.PreferenceJpaEntity;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.mapper.PreferenceMapper;
import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Adapter that implements domain PreferenceRepository interface
 * using Spring Data JPA repository.
 * Translates between domain and JPA entities using mapper.
 */
@Component
public class PreferenceRepositoryAdapter implements PreferenceRepository {

    private final SpringDataPreferenceRepository springDataRepository;
    private final EntityManager entityManager;

    public PreferenceRepositoryAdapter(SpringDataPreferenceRepository springDataRepository,
                                       EntityManager entityManager) {
        this.springDataRepository = springDataRepository;
        this.entityManager = entityManager;
    }

    @Override
    public Preference save(Preference preference) {
        // Try to find the existing managed entity first to avoid OptimisticLockException
        // when the entity was already loaded in the session
        PreferenceJpaEntity existingEntity = entityManager.find(
            PreferenceJpaEntity.class, preference.getId().getValue());
        
        if (existingEntity != null) {
            // Update the existing managed entity in-place
            existingEntity.setTenantId(preference.getTenantId().getValue());
            existingEntity.setProfileId(preference.getProfileId().getValue());
            existingEntity.setSettings(preference.getSettings());
            existingEntity.setLastUpdated(preference.getLastUpdated());
            existingEntity.setDeleted(preference.isDeleted());
            entityManager.flush();
            return PreferenceMapper.toDomainEntity(existingEntity);
        } else {
            // New entity - persist it
            PreferenceJpaEntity jpaEntity = PreferenceMapper.toJpaEntity(preference);
            entityManager.persist(jpaEntity);
            entityManager.flush();
            return PreferenceMapper.toDomainEntity(jpaEntity);
        }
    }

    @Override
    public Optional<Preference> findById(PreferenceId id) {
        return springDataRepository.findById(id.getValue())
            .map(PreferenceMapper::toDomainEntity);
    }

    @Override
    public Optional<Preference> findByKey(PreferenceKey key) {
        // Note: This requires a custom query to search within the settings map
        // For now, returning empty - can be implemented with @Query if needed
        return Optional.empty();
    }

    @Override
    public Optional<Preference> findByProfileId(ProfileId profileId) {
        return springDataRepository.findByProfileId(profileId.getValue())
            .map(PreferenceMapper::toDomainEntity);
    }

    @Override
    public Optional<Preference> findByProfileIdAndTenant(ProfileId profileId, TenantId tenantId) {
        return springDataRepository.findByTenantIdAndProfileId(
            tenantId.getValue(),
            profileId.getValue()
        ).map(PreferenceMapper::toDomainEntity);
    }

    @Override
    public void delete(Preference preference) {
        springDataRepository.deleteById(preference.getId().getValue());
    }
}
