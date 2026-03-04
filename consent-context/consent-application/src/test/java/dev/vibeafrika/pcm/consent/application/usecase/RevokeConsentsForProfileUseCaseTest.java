package dev.vibeafrika.pcm.consent.application.usecase;

import dev.vibeafrika.pcm.consent.application.port.EventPublisher;
import dev.vibeafrika.pcm.consent.domain.event.ConsentRevokedEvent;
import dev.vibeafrika.pcm.consent.domain.model.*;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit test for RevokeConsentsForProfileUseCase.
 * Tests the business logic for revoking all consents when a profile is deleted (GDPR compliance).
 */
class RevokeConsentsForProfileUseCaseTest {

    private ConsentRepository consentRepository;
    private EventPublisher eventPublisher;
    private RevokeConsentsForProfileUseCase useCase;

    @BeforeEach
    void setUp() {
        consentRepository = mock(ConsentRepository.class);
        eventPublisher = mock(EventPublisher.class);
        useCase = new RevokeConsentsForProfileUseCase(consentRepository, eventPublisher);
    }

    @Test
    void shouldRevokeAllActiveConsentsForProfile() {
        // Given: A profile with multiple active consents
        UUID profileUuid = UUID.randomUUID();
        ProfileId profileId = ProfileId.of(profileUuid);
        TenantId tenantId = TenantId.of("tenant-123");
        
        Consent consent1 = Consent.create(
            profileId,
            tenantId,
            ConsentPurpose.of("marketing"),
            ConsentScope.of("email")
        );
        
        Consent consent2 = Consent.create(
            profileId,
            tenantId,
            ConsentPurpose.of("analytics"),
            ConsentScope.of("tracking")
        );

        when(consentRepository.findActiveConsents(profileId))
            .thenReturn(Arrays.asList(consent1, consent2));
        
        when(consentRepository.save(any(Consent.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));

        // When: Use case is executed
        useCase.execute(profileUuid);

        // Then: All active consents should be revoked
        verify(consentRepository, times(1)).findActiveConsents(profileId);
        verify(consentRepository, times(2)).save(any(Consent.class));
        
        // Verify consents are revoked
        ArgumentCaptor<Consent> consentCaptor = ArgumentCaptor.forClass(Consent.class);
        verify(consentRepository, times(2)).save(consentCaptor.capture());
        
        List<Consent> savedConsents = consentCaptor.getAllValues();
        assertEquals(2, savedConsents.size());
        assertTrue(savedConsents.stream().allMatch(c -> c.getStatus() == ConsentStatus.REVOKED));
        
        // Verify events are published
        verify(eventPublisher, times(2)).publish(any(ConsentRevokedEvent.class));
    }

    @Test
    void shouldHandleProfileWithNoActiveConsents() {
        // Given: A profile with no active consents
        UUID profileUuid = UUID.randomUUID();
        ProfileId profileId = ProfileId.of(profileUuid);
        
        when(consentRepository.findActiveConsents(profileId))
            .thenReturn(Collections.emptyList());

        // When: Use case is executed
        useCase.execute(profileUuid);

        // Then: No consents should be saved or events published
        verify(consentRepository, times(1)).findActiveConsents(profileId);
        verify(consentRepository, never()).save(any(Consent.class));
        verify(eventPublisher, never()).publish(any());
    }

    @Test
    void shouldPublishEventForEachRevokedConsent() {
        // Given: A profile with one active consent
        UUID profileUuid = UUID.randomUUID();
        ProfileId profileId = ProfileId.of(profileUuid);
        TenantId tenantId = TenantId.of("tenant-456");
        ConsentPurpose purpose = ConsentPurpose.of("marketing");
        
        Consent consent = Consent.create(
            profileId,
            tenantId,
            purpose,
            ConsentScope.of("email")
        );

        when(consentRepository.findActiveConsents(profileId))
            .thenReturn(Collections.singletonList(consent));
        
        when(consentRepository.save(any(Consent.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));

        // When: Use case is executed
        useCase.execute(profileUuid);

        // Then: Event should be published with correct data
        ArgumentCaptor<ConsentRevokedEvent> eventCaptor = ArgumentCaptor.forClass(ConsentRevokedEvent.class);
        verify(eventPublisher, times(1)).publish(eventCaptor.capture());
        
        ConsentRevokedEvent event = eventCaptor.getValue();
        assertNotNull(event);
        assertEquals(consent.getId(), event.consentId());
        assertEquals(profileId, event.profileId());
        assertEquals(tenantId, event.tenantId());
        assertEquals(purpose, event.purpose());
    }
}
