package dev.vibeafrika.pcm.segment.application.usecase;

import dev.vibeafrika.pcm.segment.application.dto.DeleteSegmentRequest;
import dev.vibeafrika.pcm.segment.domain.exception.SegmentNotFoundException;
import dev.vibeafrika.pcm.segment.domain.model.Segment;
import dev.vibeafrika.pcm.segment.domain.model.SegmentId;
import dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository;

/**
 * Use case for deleting a segment.
 * No framework annotations - pure business logic.
 */
public class DeleteSegmentUseCase {
    private final SegmentRepository segmentRepository;

    // Constructor injection - no framework annotations
    public DeleteSegmentUseCase(SegmentRepository segmentRepository) {
        this.segmentRepository = segmentRepository;
    }

    /**
     * Execute the use case.
     * Transaction boundary is defined by this method scope.
     */
    public void execute(DeleteSegmentRequest request) {
        // Load segment by ID
        SegmentId segmentId = SegmentId.of(request.segmentId());
        
        Segment segment = segmentRepository.findById(segmentId)
            .orElseThrow(() -> new SegmentNotFoundException(segmentId));

        // Delete segment
        segmentRepository.delete(segment);
    }
}
