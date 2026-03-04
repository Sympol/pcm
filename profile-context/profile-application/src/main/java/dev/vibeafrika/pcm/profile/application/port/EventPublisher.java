package dev.vibeafrika.pcm.profile.application.port;

/**
 * Event publisher interface (port) for publishing domain events.
 * Defined in application layer, implemented in infrastructure layer.
 * Framework-agnostic - no Spring or CDI annotations.
 */
public interface EventPublisher {
    /**
     * Publish a domain event to the event bus.
     * Events are delivered synchronously within the same transaction.
     *
     * @param event the domain event to publish
     * @param <T> the type of the event
     */
    <T> void publish(T event);
}
