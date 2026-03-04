package dev.vibeafrika.pcm.consent.infrastructure.persistence.mapper;

import dev.vibeafrika.pcm.consent.domain.model.*;
import dev.vibeafrika.pcm.consent.infrastructure.persistence.entity.ConsentEventJpaEntity;
import dev.vibeafrika.pcm.consent.infrastructure.persistence.entity.ConsentJpaEntity;

import java.util.stream.Collectors;

/**
 * Mapper between domain Consent and JPA ConsentJpaEntity.
 */
public class ConsentMapper {

    public static ConsentJpaEntity toJpaEntity(Consent consent) {
        if (consent == null) {
            return null;
        }

        ConsentJpaEntity entity = new ConsentJpaEntity();
        entity.setId(consent.getId().getValue());
        entity.setProfileId(consent.getProfileId().getValue());
        entity.setTenantId(consent.getTenantId().getValue());
        entity.setPurpose(consent.getPurpose().getValue());
        entity.setScope(consent.getScope().getValue());
        entity.setStatus(consent.getStatus());
        entity.setCreatedAt(consent.getCreatedAt());
        entity.setUpdatedAt(consent.getUpdatedAt());
        entity.setVersion(consent.getVersion());
        
        // Map events
        consent.getHistory().forEach(event -> {
            ConsentEventJpaEntity eventEntity = new ConsentEventJpaEntity(
                event.getStatus(),
                event.getTimestamp()
            );
            eventEntity.setConsent(entity);
            entity.getEvents().add(eventEntity);
        });
        
        return entity;
    }

    public static Consent toDomainEntity(ConsentJpaEntity entity) {
        if (entity == null) {
            return null;
        }

        var events = entity.getEvents().stream()
            .map(e -> new Consent.ConsentEvent(e.getStatus(), e.getTimestamp()))
            .collect(Collectors.toList());

        return Consent.reconstitute(
            ConsentId.of(entity.getId()),
            ProfileId.of(entity.getProfileId()),
            TenantId.of(entity.getTenantId()),
            ConsentPurpose.of(entity.getPurpose()),
            ConsentScope.of(entity.getScope()),
            entity.getStatus(),
            events,
            entity.getCreatedAt(),
            entity.getUpdatedAt(),
            entity.getVersion()
        );
    }
}
