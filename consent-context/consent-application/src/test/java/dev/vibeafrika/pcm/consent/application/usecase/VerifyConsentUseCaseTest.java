package dev.vibeafrika.pcm.consent.application.usecase;

import dev.vibeafrika.pcm.consent.domain.exception.ConsentNotFoundException;
import dev.vibeafrika.pcm.consent.domain.model.*;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for VerifyConsentUseCase.
 */
class VerifyConsentUseCaseTest {

    private ConsentRepository consentRepository;
    private VerifyConsentUseCase useCase;

    private UUID consentUuid;
    private ConsentId consentId;

    @BeforeEach
    void setUp() {
        consentRepository = mock(ConsentRepository.class);
        useCase = new VerifyConsentUseCase(consentRepository);
        consentUuid = UUID.randomUUID();
        consentId = ConsentId.of(consentUuid);
    }

    @Test
    void shouldReturnTrueForActiveConsent() {
        Consent active = Consent.create(
            ProfileId.of(UUID.randomUUID()),
            TenantId.of("tenant-1"),
            ConsentPurpose.of("marketing"),
            ConsentScope.of("email")
        );
        when(consentRepository.findById(consentId)).thenReturn(Optional.of(active));

        assertTrue(useCase.execute(consentId));
    }

    @Test
    void shouldReturnFalseForRevokedConsent() {
        Consent revoked = Consent.create(
            ProfileId.of(UUID.randomUUID()),
            TenantId.of("tenant-1"),
            ConsentPurpose.of("marketing"),
            ConsentScope.of("email")
        );
        revoked.revoke();
        when(consentRepository.findById(consentId)).thenReturn(Optional.of(revoked));

        assertFalse(useCase.execute(consentId));
    }

    @Test
    void shouldThrowConsentNotFoundWhenConsentDoesNotExist() {
        when(consentRepository.findById(consentId)).thenReturn(Optional.empty());

        ConsentNotFoundException ex = assertThrows(ConsentNotFoundException.class, () ->
            useCase.execute(consentId)
        );
        assertEquals(consentId, ex.getConsentId());
    }

    @Test
    void shouldReturnTrueAfterReGrantingRevokedConsent() {
        Consent consent = Consent.create(
            ProfileId.of(UUID.randomUUID()),
            TenantId.of("tenant-1"),
            ConsentPurpose.of("analytics"),
            ConsentScope.of("tracking")
        );
        consent.revoke();
        consent.grant(); // re-grant
        when(consentRepository.findById(consentId)).thenReturn(Optional.of(consent));

        assertTrue(useCase.execute(consentId));
    }
}
