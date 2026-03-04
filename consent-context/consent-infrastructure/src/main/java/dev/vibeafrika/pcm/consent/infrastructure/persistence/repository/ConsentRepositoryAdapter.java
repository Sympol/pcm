package dev.vibeafrika.pcm.consent.infrastructure.persistence.repository;

import dev.vibeafrika.pcm.consent.domain.model.*;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;
import dev.vibeafrika.pcm.consent.infrastructure.persistence.mapper.ConsentMapper;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class ConsentRepositoryAdapter implements ConsentRepository {

    private final SpringDataConsentRepository springDataRepository;

    public ConsentRepositoryAdapter(SpringDataConsentRepository springDataRepository) {
        this.springDataRepository = springDataRepository;
    }

    @Override
    public Consent save(Consent consent) {
        var jpaEntity = ConsentMapper.toJpaEntity(consent);
        var savedEntity = springDataRepository.save(jpaEntity);
        return ConsentMapper.toDomainEntity(savedEntity);
    }

    @Override
    public Optional<Consent> findById(ConsentId id) {
        return springDataRepository.findById(id.getValue())
            .map(ConsentMapper::toDomainEntity);
    }

    @Override
    public List<Consent> findByProfile(ProfileId profileId) {
        return springDataRepository.findByProfileId(profileId.getValue()).stream()
            .map(ConsentMapper::toDomainEntity)
            .collect(Collectors.toList());
    }

    @Override
    public List<Consent> findActiveConsents(ProfileId profileId) {
        return springDataRepository.findActiveConsentsByProfileId(profileId.getValue()).stream()
            .map(ConsentMapper::toDomainEntity)
            .collect(Collectors.toList());
    }

    @Override
    public List<Consent> findByPurpose(ConsentPurpose purpose) {
        return springDataRepository.findByPurpose(purpose.getValue()).stream()
            .map(ConsentMapper::toDomainEntity)
            .collect(Collectors.toList());
    }

    @Override
    public List<Consent> getConsentHistory(ProfileId profileId) {
        // Return all consents for profile (including revoked ones) as history
        return findByProfile(profileId);
    }

    @Override
    public void delete(Consent consent) {
        springDataRepository.deleteById(consent.getId().getValue());
    }
}
