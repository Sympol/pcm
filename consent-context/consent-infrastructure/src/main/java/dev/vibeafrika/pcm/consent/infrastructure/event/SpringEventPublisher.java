package dev.vibeafrika.pcm.consent.infrastructure.event;

import dev.vibeafrika.pcm.consent.application.port.EventPublisher;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

/**
 * Spring implementation of EventPublisher interface.
 * Uses Spring's ApplicationEventPublisher to publish domain events.
 * Events are delivered synchronously within the same transaction.
 */
@Component
public class SpringEventPublisher implements EventPublisher {
    
    private final ApplicationEventPublisher applicationEventPublisher;

    public SpringEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    @Override
    public <T> void publish(T event) {
        applicationEventPublisher.publishEvent(event);
    }
}
