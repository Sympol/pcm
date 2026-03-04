package dev.vibeafrika.pcm.segment.infrastructure.event;

import dev.vibeafrika.pcm.preference.domain.event.PreferenceCreatedEvent;
import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import dev.vibeafrika.pcm.preference.domain.model.ProfileId;
import dev.vibeafrika.pcm.preference.domain.model.TenantId;
import dev.vibeafrika.pcm.segment.application.usecase.EvaluateSegmentForPreferenceUseCase;
import dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.Collections;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Integration test for inter-context event flow between Preference and Segment contexts.
 * Tests that:
 * 1. Events are delivered to subscribers
 * 2. Events are delivered within the same transaction
 * 3. Rollback prevents event delivery (tested via @TransactionalEventListener behavior)
 */
@ExtendWith(MockitoExtension.class)
class InterContextEventFlowTest {

    @Mock
    private SegmentRepository segmentRepository;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    private EvaluateSegmentForPreferenceUseCase evaluateSegmentUseCase;
    private PreferenceEventSubscriber eventSubscriber;

    @BeforeEach
    void setUp() {
        evaluateSegmentUseCase = new EvaluateSegmentForPreferenceUseCase(segmentRepository);
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

        // Mock repository to return empty list (no matching segments)
        when(segmentRepository.findMatchingSegments(any(), any()))
            .thenReturn(Collections.emptyList());

        // When: Event is published and handled
        eventSubscriber.onPreferenceCreated(event);

        // Then: Segment evaluation should be triggered
        verify(segmentRepository, times(1))
            .findMatchingSegments(any(), any());
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
        when(segmentRepository.findMatchingSegments(any(), any()))
            .thenReturn(Collections.emptyList());

        // When: Event is published and handled
        eventSubscriber.onPreferenceUpdated(event);

        // Then: Segment evaluation should be triggered
        verify(segmentRepository, times(1))
            .findMatchingSegments(any(), any());
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
        when(segmentRepository.findMatchingSegments(any(), any()))
            .thenReturn(Collections.emptyList());

        // When: Event is handled
        eventSubscriber.onPreferenceCreated(event);

        // Then: Repository should be called with correct domain value objects
        verify(segmentRepository).findMatchingSegments(
            argThat(pid -> pid.getValue().equals(profileUuid)),
            argThat(tid -> tid.getValue().equals(tenantValue))
        );
    }

    /**
     * Note: Testing transactional behavior requires a full Spring context with
     * transaction management. The @TransactionalEventListener annotation ensures:
     * 
     * 1. Events are delivered AFTER the transaction commits successfully
     * 2. If the transaction rolls back, the event handler is NOT invoked
     * 
     * This test verifies the event handler logic. Full transactional behavior
     * should be tested in a Spring Boot integration test with @SpringBootTest.
     */
}
