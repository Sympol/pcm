package dev.vibeafrika.pcm.segment.application.port;

/**
 * Port interface for publishing domain events.
 * Framework-agnostic - implemented by infrastructure layer.
 */
public interface EventPublisher {
    
    /**
     * Publish a domain event.
     * @param event the event to publish
     */
    void publish(Object event);
}
