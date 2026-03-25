package dev.vibeafrika.pcm.consent.application.usecase;

import dev.vibeafrika.pcm.consent.application.dto.ConsentResponse;
import dev.vibeafrika.pcm.consent.application.dto.RevokeConsentRequest;
import dev.vibeafrika.pcm.consent.application.port.EventPublisher;
import dev.vibeafrika.pcm.consent.domain.event.ConsentRevokedEvent;
import dev.vibeafrika.pcm.consent.domain.exception.ConsentNotFoundException;
import dev.vibeafrika.pcm.consent.domain.exception.ConsentRevokedException;
import dev.vibeafrika.pcm.consent.domain.model.*;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for RevokeConsentUseCase.
 */
class RevokeConsentUseCaseTest {

    private ConsentRepository consentRepository;
    private EventPublisher eventPublisher;
    private RevokeConsentUseCase useCase;

    private Consent activeConsent;
    private UUID consentUuid;

    @BeforeEach
    void setUp() {
        consentRepository = mock(ConsentRepository.class);
        eventPublisher = mock(EventPublisher.class);
        useCase = new RevokeConsentUseCase(consentRepository, eventPublisher);

        consentUuid = UUID.randomUUID();
        activeConsent = Consent.create(
            ProfileId.of(UUID.randomUUID()),
            TenantId.of("tenant-1"),
            ConsentPurpose.of("marketing"),
            ConsentScope.of("email")
        );
        when(consentRepository.save(any(Consent.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void shouldRevokeActiveConsent() {
        when(consentRepository.findById(ConsentId.of(consentUuid)))
            .thenReturn(Optional.of(activeConsent));

        ConsentResponse response = useCase.execute(new RevokeConsentRequest(consentUuid, "tenant-1"));

        assertEquals("REVOKED", response.status());
    }

    @Test
    void shouldPersistRevokedConsent() {
        when(consentRepository.findById(ConsentId.of(consentUuid)))
            .thenReturn(Optional.of(activeConsent));

        useCase.execute(new RevokeConsentRequest(consentUuid, "tenant-1"));

        ArgumentCaptor<Consent> captor = ArgumentCaptor.forClass(Consent.class);
        verify(consentRepository).save(captor.capture());
        assertEquals(ConsentStatus.REVOKED, captor.getValue().getStatus());
    }

    @Test
    void shouldPublishConsentRevokedEvent() {
        when(consentRepository.findById(ConsentId.of(consentUuid)))
            .thenReturn(Optional.of(activeConsent));

        useCase.execute(new RevokeConsentRequest(consentUuid, "tenant-1"));

        ArgumentCaptor<ConsentRevokedEvent> eventCaptor = ArgumentCaptor.forClass(ConsentRevokedEvent.class);
        verify(eventPublisher).publish(eventCaptor.capture());
        ConsentRevokedEvent event = eventCaptor.getValue();
        assertNotNull(event.consentId());
        assertEquals(activeConsent.getProfileId(), event.profileId());
        assertEquals(activeConsent.getPurpose(), event.purpose());
    }

    @Test
    void shouldThrowConsentNotFoundWhenConsentDoesNotExist() {
        when(consentRepository.findById(ConsentId.of(consentUuid)))
            .thenReturn(Optional.empty());

        assertThrows(ConsentNotFoundException.class, () ->
            useCase.execute(new RevokeConsentRequest(consentUuid, "tenant-1"))
        );
        verify(consentRepository, never()).save(any());
        verify(eventPublisher, never()).publish(any());
    }

    @Test
    void shouldThrowConsentRevokedWhenAlreadyRevoked() {
        activeConsent.revoke(); // pre-revoke
        when(consentRepository.findById(ConsentId.of(consentUuid)))
            .thenReturn(Optional.of(activeConsent));

        assertThrows(ConsentRevokedException.class, () ->
            useCase.execute(new RevokeConsentRequest(consentUuid, "tenant-1"))
        );
        verify(consentRepository, never()).save(any());
    }

    @Test
    void shouldAddRevocationEventToConsentLedger() {
        when(consentRepository.findById(ConsentId.of(consentUuid)))
            .thenReturn(Optional.of(activeConsent));

        useCase.execute(new RevokeConsentRequest(consentUuid, "tenant-1"));

        // Initial grant event + revocation event = 2 events
        assertEquals(2, activeConsent.getHistory().size());
        assertEquals(ConsentStatus.REVOKED, activeConsent.getHistory().get(1).getStatus());
    }
}
