package dev.vibeafrika.pcm.segment.application.usecase;

import dev.vibeafrika.pcm.segment.application.dto.EvaluateSegmentRequest;
import dev.vibeafrika.pcm.segment.application.dto.SegmentResponse;
import dev.vibeafrika.pcm.segment.domain.model.ProfileId;
import dev.vibeafrika.pcm.segment.domain.model.Segment;
import dev.vibeafrika.pcm.segment.domain.model.TenantId;
import dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Use case for evaluating which segments match a profile.
 * No framework annotations - pure business logic.
 */
public class EvaluateSegmentUseCase {
    private final SegmentRepository segmentRepository;

    // Constructor injection - no framework annotations
    public EvaluateSegmentUseCase(SegmentRepository segmentRepository) {
        this.segmentRepository = segmentRepository;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public List<SegmentResponse> execute(EvaluateSegmentRequest request) {
        // Create domain value objects
        ProfileId profileId = ProfileId.of(request.profileId());
        TenantId tenantId = TenantId.of(request.tenantId());

        // Find matching segments
        List<Segment> matchingSegments = segmentRepository.findMatchingSegments(profileId, tenantId);

        // Convert to DTOs
        return matchingSegments.stream()
            .map(SegmentResponse::from)
            .collect(Collectors.toList());
    }
}
