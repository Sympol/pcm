package dev.vibeafrika.pcm.segment.domain.event;

import dev.vibeafrika.pcm.segment.domain.model.ProfileId;
import dev.vibeafrika.pcm.segment.domain.model.SegmentId;
import dev.vibeafrika.pcm.segment.domain.model.TenantId;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * Event published when a segment is updated.
 */
public record SegmentUpdatedEvent(
    SegmentId segmentId,
    ProfileId profileId,
    TenantId tenantId,
    Set<String> tags,
    Map<String, Double> scores,
    Instant occurredAt
) {
    public SegmentUpdatedEvent {
        tags = tags != null ? Set.copyOf(tags) : Set.of();
        scores = scores != null ? Map.copyOf(scores) : Map.of();
    }

    public static SegmentUpdatedEvent of(
        SegmentId segmentId,
        ProfileId profileId,
        TenantId tenantId,
        Set<String> tags,
        Map<String, Double> scores
    ) {
        return new SegmentUpdatedEvent(segmentId, profileId, tenantId, tags, scores, Instant.now());
    }
}
