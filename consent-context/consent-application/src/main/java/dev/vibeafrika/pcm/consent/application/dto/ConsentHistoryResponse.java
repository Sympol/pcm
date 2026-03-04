package dev.vibeafrika.pcm.consent.application.dto;

import dev.vibeafrika.pcm.consent.domain.model.Consent;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Response DTO for consent history.
 * No framework annotations - pure data carrier.
 */
public record ConsentHistoryResponse(
    List<ConsentEventDto> events
) {
    public static ConsentHistoryResponse from(Consent consent) {
        List<ConsentEventDto> eventDtos = consent.getHistory().stream()
            .map(event -> new ConsentEventDto(
                event.getStatus().name(),
                event.getTimestamp().toString()
            ))
            .collect(Collectors.toList());
        
        return new ConsentHistoryResponse(eventDtos);
    }

    public record ConsentEventDto(
        String status,
        String timestamp
    ) {}
}
