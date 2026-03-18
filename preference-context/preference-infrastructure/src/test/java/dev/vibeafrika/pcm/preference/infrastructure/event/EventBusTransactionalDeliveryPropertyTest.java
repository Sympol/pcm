package dev.vibeafrika.pcm.preference.infrastructure.event;

import dev.vibeafrika.pcm.preference.application.port.EventPublisher;
import dev.vibeafrika.pcm.preference.domain.event.PreferenceCreatedEvent;
import dev.vibeafrika.pcm.preference.domain.event.PreferenceUpdatedEvent;
import dev.vibeafrika.pcm.preference.domain.model.PreferenceId;
import dev.vibeafrika.pcm.preference.domain.model.ProfileId;
import dev.vibeafrika.pcm.preference.domain.model.TenantId;
import net.jqwik.api.*;
import net.jqwik.api.lifecycle.BeforeProperty;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Property-based tests for the event bus transactional delivery contract.
 *
 * <p>Property 26: Event Bus Delivers Events Within Transaction
 *
 * <p>These tests verify that:
 * 1. Every event published via EventPublisher is delivered to all registered listeners
 * 2. Events are delivered synchronously (within the same call stack)
 * 3. Multiple events published in sequence are all delivered in order
 * 4. The SpringEventPublisher correctly delegates to ApplicationEventPublisher
 * 5. When the publisher throws, no events are silently swallowed
 */
class EventBusTransactionalDeliveryPropertyTest {

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * In-memory ApplicationEventPublisher that records published events and
     * dispatches them synchronously to registered listeners — simulating
     * Spring's synchronous in-process event delivery.
     */
    static class RecordingEventPublisher implements ApplicationEventPublisher {

        private final List<Object> publishedEvents = new ArrayList<>();
        private final List<Runnable> listeners = new ArrayList<>();

        @Override
        public void publishEvent(Object event) {
            publishedEvents.add(event);
            listeners.forEach(Runnable::run);
        }

        void addListener(Runnable listener) {
            listeners.add(listener);
        }

        List<Object> getPublishedEvents() {
            return List.copyOf(publishedEvents);
        }

        void reset() {
            publishedEvents.clear();
        }
    }

    /**
     * Failing ApplicationEventPublisher that simulates a rollback scenario:
     * throws a RuntimeException when an event is published, modelling the
     * case where the transaction is rolled back before delivery completes.
     */
    static class FailingEventPublisher implements ApplicationEventPublisher {
        @Override
        public void publishEvent(Object event) {
            throw new RuntimeException("Simulated transaction rollback — event delivery aborted");
        }
    }

    private RecordingEventPublisher recordingPublisher;
    private EventPublisher eventPublisher;

    @BeforeEach
    void setUp() {
        recordingPublisher = new RecordingEventPublisher();
        eventPublisher = new SpringEventPublisher(recordingPublisher);
    }

    @BeforeProperty
    void setUpForProperty() {
        recordingPublisher = new RecordingEventPublisher();
        eventPublisher = new SpringEventPublisher(recordingPublisher);
    }

    // -------------------------------------------------------------------------
    // Property 26 — core delivery guarantee
    // -------------------------------------------------------------------------

    /**
     * For any valid PreferenceCreatedEvent, publishing it via EventPublisher
     * must result in exactly one event being delivered to the underlying bus.
     *
     * <p>Validates: events delivered within the same transaction.
     */
    @Property(tries = 200)
    @Label("Every PreferenceCreatedEvent published is delivered exactly once")
    void everyPreferenceCreatedEventIsDeliveredExactlyOnce(
            @ForAll("preferenceCreatedEvents") PreferenceCreatedEvent event) {

        recordingPublisher.reset();

        eventPublisher.publish(event);

        assertThat(recordingPublisher.getPublishedEvents())
                .as("Expected exactly one event to be delivered for %s", event)
                .hasSize(1)
                .containsExactly(event);
    }

    /**
     * For any valid PreferenceUpdatedEvent, publishing it via EventPublisher
     * must result in exactly one event being delivered to the underlying bus.
     *
     */
    @Property(tries = 200)
    @Label("Every PreferenceUpdatedEvent published is delivered exactly once")
    void everyPreferenceUpdatedEventIsDeliveredExactlyOnce(
            @ForAll("preferenceUpdatedEvents") PreferenceUpdatedEvent event) {

        recordingPublisher.reset();

        eventPublisher.publish(event);

        assertThat(recordingPublisher.getPublishedEvents())
                .as("Expected exactly one event to be delivered for %s", event)
                .hasSize(1)
                .containsExactly(event);
    }

    /**
     * For any sequence of N events (1–50), all N events must be delivered
     * in the exact order they were published.
     *
     * <p>Validates: synchronous, ordered delivery.
     */
    @Property(tries = 100)
    @Label("Multiple events are delivered in publication order")
    void multipleEventsAreDeliveredInOrder(
            @ForAll("eventSequences") List<PreferenceCreatedEvent> events) {

        recordingPublisher.reset();

        events.forEach(eventPublisher::publish);

        assertThat(recordingPublisher.getPublishedEvents())
                .as("All %d events must be delivered in order", events.size())
                .hasSize(events.size())
                .containsExactlyElementsOf(events);
    }

    /**
     * For any number of listeners (1–10), every listener must be notified
     * when an event is published — simulating multiple bounded context subscribers.
     *
     * <p>Validates: all registered subscribers receive the event.
     */
    @Property(tries = 100)
    @Label("All registered listeners are notified for each published event")
    void allListenersAreNotifiedOnEventPublish(
            @ForAll("listenerCounts") int listenerCount,
            @ForAll("preferenceCreatedEvents") PreferenceCreatedEvent event) {

        // Fresh publisher per try to avoid listener accumulation across tries
        RecordingEventPublisher freshPublisher = new RecordingEventPublisher();
        EventPublisher freshEventPublisher = new SpringEventPublisher(freshPublisher);
        AtomicInteger notificationCount = new AtomicInteger(0);

        for (int i = 0; i < listenerCount; i++) {
            freshPublisher.addListener(notificationCount::incrementAndGet);
        }

        freshEventPublisher.publish(event);

        assertThat(notificationCount.get())
                .as("Expected %d listener notifications but got %d", listenerCount, notificationCount.get())
                .isEqualTo(listenerCount);
    }

    // -------------------------------------------------------------------------
    // Rollback / failure scenario
    // -------------------------------------------------------------------------

    /**
     * When the underlying ApplicationEventPublisher throws (simulating a
     * transaction rollback), the exception must propagate — no silent swallowing.
     *
     * <p>Validates: rollback prevents event delivery.
     */
    @Test
    void whenPublisherThrowsExceptionPropagates() {
        EventPublisher failingPublisher = new SpringEventPublisher(new FailingEventPublisher());

        PreferenceCreatedEvent event = PreferenceCreatedEvent.of(
                PreferenceId.generate(),
                TenantId.of("tenant-1"),
                ProfileId.of(UUID.randomUUID())
        );

        assertThatThrownBy(() -> failingPublisher.publish(event))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Simulated transaction rollback");
    }

    /**
     * Delivery is synchronous: the listener is invoked before publish() returns.
     *
     * <p>Validates: synchronous delivery within the same transaction.
     */
    @Test
    void eventDeliveryIsSynchronous() {
        AtomicBoolean listenerInvoked = new AtomicBoolean(false);
        recordingPublisher.addListener(() -> listenerInvoked.set(true));

        PreferenceCreatedEvent event = PreferenceCreatedEvent.of(
                PreferenceId.generate(),
                TenantId.of("tenant-sync"),
                ProfileId.of(UUID.randomUUID())
        );

        // Listener must be invoked synchronously — before this assertion runs
        eventPublisher.publish(event);

        assertThat(listenerInvoked.get())
                .as("Listener must be invoked synchronously within publish()")
                .isTrue();
    }

    // -------------------------------------------------------------------------
    // Arbitraries
    // -------------------------------------------------------------------------

    @Provide
    Arbitrary<PreferenceCreatedEvent> preferenceCreatedEvents() {
        return Arbitraries.randomValue(random ->
                PreferenceCreatedEvent.of(
                        PreferenceId.generate(),
                        TenantId.of("tenant-" + Math.abs(random.nextInt() % 1000)),
                        ProfileId.of(UUID.randomUUID())
                )
        );
    }

    @Provide
    Arbitrary<PreferenceUpdatedEvent> preferenceUpdatedEvents() {
        return Arbitraries.randomValue(random ->
                PreferenceUpdatedEvent.of(
                        PreferenceId.generate(),
                        TenantId.of("tenant-" + Math.abs(random.nextInt() % 1000)),
                        ProfileId.of(UUID.randomUUID())
                )
        );
    }

    @Provide
    Arbitrary<List<PreferenceCreatedEvent>> eventSequences() {
        return Arbitraries.integers().between(1, 50).flatMap(size ->
                Arbitraries.randomValue(random -> {
                    List<PreferenceCreatedEvent> events = new ArrayList<>(size);
                    for (int i = 0; i < size; i++) {
                        events.add(PreferenceCreatedEvent.of(
                                PreferenceId.generate(),
                                TenantId.of("tenant-" + i),
                                ProfileId.of(UUID.randomUUID())
                        ));
                    }
                    return events;
                })
        );
    }

    @Provide
    Arbitrary<Integer> listenerCounts() {
        return Arbitraries.integers().between(1, 10);
    }
}
