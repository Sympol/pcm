package dev.vibeafrika.pcm.segment.application.usecase;

import dev.vibeafrika.pcm.segment.application.dto.UpdateSegmentRequest;
import dev.vibeafrika.pcm.segment.application.dto.SegmentResponse;
import dev.vibeafrika.pcm.segment.domain.exception.SegmentNotFoundException;
import dev.vibeafrika.pcm.segment.domain.model.Segment;
import dev.vibeafrika.pcm.segment.domain.model.SegmentId;
import dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository;

/**
 * Use case for updating segment tags and scores.
 * No framework annotations - pure business logic.
 */
public class UpdateSegmentUseCase {
    private final SegmentRepository segmentRepository;

    // Constructor injection - no framework annotations
    public UpdateSegmentUseCase(SegmentRepository segmentRepository) {
        this.segmentRepository = segmentRepository;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public SegmentResponse execute(UpdateSegmentRequest request) {
        // Load segment by ID
        SegmentId segmentId = SegmentId.of(request.segmentId());
        
        Segment segment = segmentRepository.findById(segmentId)
            .orElseThrow(() -> new SegmentNotFoundException(segmentId));

        // Update domain entity (enforces business rules)
        segment.updateSegments(request.tags(), request.scores());

        // Persist
        Segment updatedSegment = segmentRepository.save(segment);

        // Return DTO
        return SegmentResponse.from(updatedSegment);
    }
}
