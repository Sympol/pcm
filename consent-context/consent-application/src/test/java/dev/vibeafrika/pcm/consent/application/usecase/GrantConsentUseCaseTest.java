package dev.vibeafrika.pcm.consent.application.usecase;

import dev.vibeafrika.pcm.consent.application.dto.ConsentResponse;
import dev.vibeafrika.pcm.consent.application.dto.GrantConsentRequest;
import dev.vibeafrika.pcm.consent.application.port.EventPublisher;
import dev.vibeafrika.pcm.consent.domain.event.ConsentGrantedEvent;
import dev.vibeafrika.pcm.consent.domain.model.*;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for GrantConsentUseCase.
 */
class GrantConsentUseCaseTest {

    private ConsentRepository consentRepository;
    private EventPublisher eventPublisher;
    private GrantConsentUseCase useCase;

    @BeforeEach
    void setUp() {
        consentRepository = mock(ConsentRepository.class);
        eventPublisher = mock(EventPublisher.class);
        useCase = new GrantConsentUseCase(consentRepository, eventPublisher);
        when(consentRepository.save(any(Consent.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void shouldGrantConsentAndReturnResponse() {
        UUID profileUuid = UUID.randomUUID();
        GrantConsentRequest request = new GrantConsentRequest(
            profileUuid, "tenant-1", "marketing", "email"
        );

        ConsentResponse response = useCase.execute(request);

        assertNotNull(response);
        assertEquals(profileUuid, response.profileId());
        assertEquals("tenant-1", response.tenantId());
        assertEquals("marketing", response.purpose());
        assertEquals("email", response.scope());
        assertEquals("GRANTED", response.status());
    }

    @Test
    void shouldPersistConsentOnGrant() {
        GrantConsentRequest request = new GrantConsentRequest(
            UUID.randomUUID(), "tenant-1", "analytics", "tracking"
        );

        useCase.execute(request);

        ArgumentCaptor<Consent> captor = ArgumentCaptor.forClass(Consent.class);
        verify(consentRepository).save(captor.capture());
        Consent saved = captor.getValue();
        assertEquals(ConsentStatus.GRANTED, saved.getStatus());
        assertEquals("analytics", saved.getPurpose().getValue());
        assertEquals("tracking", saved.getScope().getValue());
    }

    @Test
    void shouldPublishConsentGrantedEvent() {
        UUID profileUuid = UUID.randomUUID();
        GrantConsentRequest request = new GrantConsentRequest(
            profileUuid, "tenant-1", "marketing", "email"
        );

        useCase.execute(request);

        ArgumentCaptor<ConsentGrantedEvent> eventCaptor = ArgumentCaptor.forClass(ConsentGrantedEvent.class);
        verify(eventPublisher).publish(eventCaptor.capture());
        ConsentGrantedEvent event = eventCaptor.getValue();
        assertNotNull(event.consentId());
        assertEquals(ProfileId.of(profileUuid), event.profileId());
        assertEquals(TenantId.of("tenant-1"), event.tenantId());
        assertEquals(ConsentPurpose.of("marketing"), event.purpose());
    }

    @Test
    void shouldFailWhenProfileIdIsNull() {
        assertThrows(IllegalArgumentException.class, () ->
            new GrantConsentRequest(null, "tenant-1", "marketing", "email")
        );
    }

    @Test
    void shouldFailWhenTenantIdIsBlank() {
        assertThrows(IllegalArgumentException.class, () ->
            new GrantConsentRequest(UUID.randomUUID(), "", "marketing", "email")
        );
    }

    @Test
    void shouldFailWhenPurposeIsBlank() {
        assertThrows(IllegalArgumentException.class, () ->
            new GrantConsentRequest(UUID.randomUUID(), "tenant-1", "", "email")
        );
    }

    @Test
    void shouldFailWhenScopeIsBlank() {
        assertThrows(IllegalArgumentException.class, () ->
            new GrantConsentRequest(UUID.randomUUID(), "tenant-1", "marketing", "")
        );
    }
}
