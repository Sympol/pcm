package dev.vibeafrika.pcm.profile.infrastructure.persistence.repository;

import dev.vibeafrika.pcm.profile.domain.model.*;
import dev.vibeafrika.pcm.profile.domain.repository.ProfileRepository;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.entity.ProfileJpaEntity;
import dev.vibeafrika.pcm.profile.infrastructure.persistence.mapper.ProfileMapper;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Adapter that implements domain ProfileRepository interface
 * using Spring Data JPA repository.
 */
@Component
public class ProfileRepositoryAdapter implements ProfileRepository {

    private final SpringDataProfileRepository springDataRepository;

    public ProfileRepositoryAdapter(SpringDataProfileRepository springDataRepository) {
        this.springDataRepository = springDataRepository;
    }

    @Override
    public Profile save(Profile profile) {
        ProfileJpaEntity jpaEntity = ProfileMapper.toJpaEntity(profile);
        ProfileJpaEntity savedEntity = springDataRepository.save(jpaEntity);
        return ProfileMapper.toDomainEntity(savedEntity);
    }

    @Override
    public Optional<Profile> findById(ProfileId id) {
        return springDataRepository.findById(id.getValue())
            .map(ProfileMapper::toDomainEntity);
    }

    @Override
    public Optional<Profile> findByHandle(Handle handle, TenantId tenantId) {
        return springDataRepository.findByHandleAndTenantId(handle.getValue(), tenantId.getValue())
            .map(ProfileMapper::toDomainEntity);
    }

    @Override
    public Optional<Profile> findByIdAndTenant(ProfileId id, TenantId tenantId) {
        return springDataRepository.findByIdAndTenantId(id.getValue(), tenantId.getValue())
            .map(ProfileMapper::toDomainEntity);
    }

    @Override
    public boolean existsByHandle(Handle handle, TenantId tenantId) {
        return springDataRepository.existsByHandleAndTenantId(handle.getValue(), tenantId.getValue());
    }

    @Override
    public void delete(Profile profile) {
        springDataRepository.deleteById(profile.getId().getValue());
    }
}
