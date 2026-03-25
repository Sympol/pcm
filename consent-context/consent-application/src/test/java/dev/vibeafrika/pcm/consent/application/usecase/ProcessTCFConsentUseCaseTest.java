package dev.vibeafrika.pcm.consent.application.usecase;

import dev.vibeafrika.pcm.consent.application.dto.ConsentResponse;
import dev.vibeafrika.pcm.consent.application.dto.TCFConsentRequest;
import dev.vibeafrika.pcm.consent.domain.model.Consent;
import dev.vibeafrika.pcm.consent.domain.repository.ConsentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for ProcessTCFConsentUseCase.
 */
class ProcessTCFConsentUseCaseTest {

    private ConsentRepository consentRepository;
    private ProcessTCFConsentUseCase useCase;

    private static final String VALID_TC_STRING = "CPXxRfAPXxRfAAfKABENB-CgAAAAAAAAAAYgAAAAAAAA";

    @BeforeEach
    void setUp() {
        consentRepository = mock(ConsentRepository.class);
        useCase = new ProcessTCFConsentUseCase(consentRepository);
        when(consentRepository.save(any(Consent.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void shouldProcessTCFConsentWithVendorAndPurpose() {
        UUID profileUuid = UUID.randomUUID();
        TCFConsentRequest request = new TCFConsentRequest(
            profileUuid, "tenant-1", VALID_TC_STRING, 42, 3
        );

        ConsentResponse response = useCase.execute(request);

        assertNotNull(response);
        assertEquals(profileUuid, response.profileId());
        assertEquals("tenant-1", response.tenantId());
        assertEquals("GRANTED", response.status());
        assertTrue(response.purpose().startsWith("TCF_"));
        assertTrue(response.scope().startsWith("TCF_VENDOR_"));
    }

    @Test
    void shouldProcessTCFConsentWithoutVendorOrPurpose() {
        TCFConsentRequest request = new TCFConsentRequest(
            UUID.randomUUID(), "tenant-1", VALID_TC_STRING, null, null
        );

        ConsentResponse response = useCase.execute(request);

        assertEquals("TCF_GENERAL", response.purpose());
        assertEquals("TCF_VENDOR_ALL", response.scope());
    }

    @Test
    void shouldEncodeVendorIdInScope() {
        TCFConsentRequest request = new TCFConsentRequest(
            UUID.randomUUID(), "tenant-1", VALID_TC_STRING, 99, null
        );

        ConsentResponse response = useCase.execute(request);

        assertEquals("TCF_VENDOR_99", response.scope());
    }

    @Test
    void shouldEncodePurposeIdInPurpose() {
        TCFConsentRequest request = new TCFConsentRequest(
            UUID.randomUUID(), "tenant-1", VALID_TC_STRING, null, 7
        );

        ConsentResponse response = useCase.execute(request);

        assertEquals("TCF_7", response.purpose());
    }

    @Test
    void shouldPersistTCFConsent() {
        TCFConsentRequest request = new TCFConsentRequest(
            UUID.randomUUID(), "tenant-1", VALID_TC_STRING, 1, 1
        );

        useCase.execute(request);

        ArgumentCaptor<Consent> captor = ArgumentCaptor.forClass(Consent.class);
        verify(consentRepository).save(captor.capture());
        assertNotNull(captor.getValue().getId());
    }

    @Test
    void shouldFailWhenTCStringIsTooShort() {
        assertThrows(Exception.class, () ->
            new TCFConsentRequest(UUID.randomUUID(), "tenant-1", "short", 1, 1)
        );
    }

    @Test
    void shouldFailWhenProfileIdIsNull() {
        assertThrows(IllegalArgumentException.class, () ->
            new TCFConsentRequest(null, "tenant-1", VALID_TC_STRING, 1, 1)
        );
    }

    @Test
    void shouldFailWhenTenantIdIsBlank() {
        assertThrows(IllegalArgumentException.class, () ->
            new TCFConsentRequest(UUID.randomUUID(), "", VALID_TC_STRING, 1, 1)
        );
    }
}
