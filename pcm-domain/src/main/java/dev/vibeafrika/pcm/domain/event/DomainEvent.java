package dev.vibeafrika.pcm.domain.event;

import java.time.Instant;
import java.util.UUID;

/**
 * Base interface for all domain events across bounded contexts.
 */
public interface DomainEvent {
    
    /**
     * Unique identifier for this event instance.
     */
    UUID eventId();
    
    /**
     * Timestamp when the event occurred.
     */
    Instant occurredAt();
}
