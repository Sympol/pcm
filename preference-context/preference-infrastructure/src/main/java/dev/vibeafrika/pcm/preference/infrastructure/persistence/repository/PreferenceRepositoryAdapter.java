package dev.vibeafrika.pcm.preference.infrastructure.persistence.repository;

import dev.vibeafrika.pcm.preference.domain.model.*;
import dev.vibeafrika.pcm.preference.domain.repository.PreferenceRepository;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.entity.PreferenceJpaEntity;
import dev.vibeafrika.pcm.preference.infrastructure.persistence.mapper.PreferenceMapper;
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

    public PreferenceRepositoryAdapter(SpringDataPreferenceRepository springDataRepository) {
        this.springDataRepository = springDataRepository;
    }

    @Override
    public Preference save(Preference preference) {
        PreferenceJpaEntity jpaEntity = PreferenceMapper.toJpaEntity(preference);
        PreferenceJpaEntity savedEntity = springDataRepository.save(jpaEntity);
        return PreferenceMapper.toDomainEntity(savedEntity);
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
