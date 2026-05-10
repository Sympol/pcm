package dev.vibeafrika.pcm.segment.infrastructure.event;

import dev.vibeafrika.pcm.preference.domain.event.PreferenceCreatedEvent;
import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import dev.vibeafrika.pcm.preference.domain.model.ProfileId;
import dev.vibeafrika.pcm.preference.domain.model.TenantId;
import dev.vibeafrika.pcm.segment.application.port.EventPublisher;
import dev.vibeafrika.pcm.segment.application.port.PreferenceProvider;
import dev.vibeafrika.pcm.segment.application.port.ProfileProvider;
import dev.vibeafrika.pcm.segment.application.usecase.EvaluateSegmentForPreferenceUseCase;
import dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository;
import dev.vibeafrika.pcm.segment.domain.service.SegmentEvaluationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Integration test for inter-context event flow between Preference and Segment contexts.
 */
@ExtendWith(MockitoExtension.class)
class InterContextEventFlowTest {

    @Mock
    private SegmentRepository segmentRepository;

    @Mock
    private ProfileProvider profileProvider;

    @Mock
    private PreferenceProvider preferenceProvider;

    @Mock
    private EventPublisher segmentEventPublisher;

    @Mock
    private SegmentEvaluationService evaluationService;

    private EvaluateSegmentForPreferenceUseCase evaluateSegmentUseCase;
    private PreferenceEventSubscriber eventSubscriber;

    @BeforeEach
    void setUp() {
        evaluateSegmentUseCase = new EvaluateSegmentForPreferenceUseCase(
                segmentRepository, profileProvider, preferenceProvider, segmentEventPublisher, evaluationService);
        eventSubscriber = new PreferenceEventSubscriber(evaluateSegmentUseCase);
    }

    @Test
    void shouldHandlePreferenceCreatedEvent() {
        // Given: A preference created event
        PreferenceId preferenceId = PreferenceId.generate();
        TenantId tenantId = TenantId.of("tenant-123");
        ProfileId profileId = ProfileId.generate();
        
        PreferenceCreatedEvent event = PreferenceCreatedEvent.of(
            preferenceId,
            tenantId,
            profileId
        );

        // Mock repository to return empty list
        when(segmentRepository.findByProfile(any(), any()))
            .thenReturn(Collections.emptyList());
        
        // Mock profile provider
        when(profileProvider.getProfileSnapshot(any()))
            .thenReturn(Optional.of(new ProfileProvider.ProfileSnapshot(profileId.getValue(), "handle", Collections.emptyMap())));

        // When: Event is published and handled
        eventSubscriber.onPreferenceCreated(event);

        // Then: Segment evaluation should be triggered
        verify(segmentRepository, times(1))
            .findByProfile(any(), any());
    }

    @Test
    void shouldHandlePreferenceUpdatedEvent() {
        // Given: A preference updated event
        PreferenceId preferenceId = PreferenceId.generate();
        TenantId tenantId = TenantId.of("tenant-456");
        ProfileId profileId = ProfileId.generate();
        
        dev.vibeafrika.pcm.preference.domain.event.PreferenceUpdatedEvent event = 
            dev.vibeafrika.pcm.preference.domain.event.PreferenceUpdatedEvent.of(
                preferenceId,
                tenantId,
                profileId
            );

        // Mock repository to return empty list
        when(segmentRepository.findByProfile(any(), any()))
            .thenReturn(Collections.emptyList());

        // Mock profile provider
        when(profileProvider.getProfileSnapshot(any()))
            .thenReturn(Optional.of(new ProfileProvider.ProfileSnapshot(profileId.getValue(), "handle", Collections.emptyMap())));

        // When: Event is published and handled
        eventSubscriber.onPreferenceUpdated(event);

        // Then: Segment evaluation should be triggered
        verify(segmentRepository, times(1))
            .findByProfile(any(), any());
    }

    @Test
    void shouldPassCorrectParametersToUseCase() {
        // Given: A preference created event with specific values
        UUID profileUuid = UUID.randomUUID();
        String tenantValue = "tenant-789";
        
        PreferenceId preferenceId = PreferenceId.generate();
        TenantId tenantId = TenantId.of(tenantValue);
        ProfileId profileId = ProfileId.of(profileUuid);
        
        PreferenceCreatedEvent event = PreferenceCreatedEvent.of(
            preferenceId,
            tenantId,
            profileId
        );

        // Mock repository
        when(segmentRepository.findByProfile(any(), any()))
            .thenReturn(Collections.emptyList());

        // Mock profile provider
        when(profileProvider.getProfileSnapshot(any()))
            .thenReturn(Optional.of(new ProfileProvider.ProfileSnapshot(profileUuid, "handle", Collections.emptyMap())));

        // When: Event is handled
        eventSubscriber.onPreferenceCreated(event);

        // Then: Repository should be called with correct domain value objects
        verify(segmentRepository).findByProfile(
            argThat(pid -> pid.getValue().equals(profileUuid)),
            argThat(tid -> tid.getValue().equals(tenantValue))
        );
    }
}
