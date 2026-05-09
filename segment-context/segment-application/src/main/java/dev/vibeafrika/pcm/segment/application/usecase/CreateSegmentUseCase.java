package dev.vibeafrika.pcm.segment.application.usecase;

import dev.vibeafrika.pcm.segment.application.dto.CreateSegmentRequest;
import dev.vibeafrika.pcm.segment.application.dto.SegmentResponse;
import dev.vibeafrika.pcm.segment.domain.model.ProfileId;
import dev.vibeafrika.pcm.segment.domain.model.Segment;
import dev.vibeafrika.pcm.segment.domain.model.TenantId;
import dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository;

/**
 * Use case for creating a new segment.
 * No framework annotations - pure business logic.
 */
public class CreateSegmentUseCase {
    private final SegmentRepository segmentRepository;

    // Constructor injection - no framework annotations
    public CreateSegmentUseCase(SegmentRepository segmentRepository) {
        this.segmentRepository = segmentRepository;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public SegmentResponse execute(CreateSegmentRequest request) {
        // Create domain value objects
        TenantId tenantId = TenantId.of(request.tenantId());
        ProfileId profileId = ProfileId.of(request.profileId());

        // Create domain entity
        Segment segment = Segment.create(tenantId, profileId, request.tags(), request.scores());

        // Persist
        Segment savedSegment = segmentRepository.save(segment);

        // Return DTO
        return SegmentResponse.from(savedSegment);
    }
}
