package dev.vibeafrika.pcm.segment.application.usecase;

import dev.vibeafrika.pcm.segment.domain.model.ProfileId;
import dev.vibeafrika.pcm.segment.domain.model.Segment;
import dev.vibeafrika.pcm.segment.domain.model.TenantId;
import dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository;

import java.util.List;
import java.util.UUID;

/**
 * Use case for evaluating segments when a profile is created or updated.
 * This use case is triggered by inter-context events from the Profile context.
 * No framework annotations - pure business logic.
 */
public class EvaluateSegmentForProfileUseCase {
    private final SegmentRepository segmentRepository;

    // Constructor injection - no framework annotations
    public EvaluateSegmentForProfileUseCase(SegmentRepository segmentRepository) {
        this.segmentRepository = segmentRepository;
    }

    /**
     * Execute the use case.
     * Evaluates which segments match the profile.
     * Transaction boundary is defined by this method scope.
     *
     * @param profileId the profile ID from the profile event
     * @param tenantId the tenant ID from the profile event
     */
    public void execute(UUID profileId, String tenantId) {
        // Create domain value objects
        ProfileId domainProfileId = ProfileId.of(profileId);
        TenantId domainTenantId = TenantId.of(tenantId);

        // Find matching segments for this profile
        List<Segment> matchingSegments = segmentRepository.findMatchingSegments(domainProfileId, domainTenantId);

        // Business logic: Evaluate segment membership
        // In a real implementation, this might:
        // - Update segment membership tables
        // - Trigger notifications when profile enters/exits segments
        // - Update analytics and metrics
        // - Publish segment membership events
        // For now, we just evaluate and the repository handles any side effects
        
        // The evaluation itself is the business logic - finding which segments match
        // Additional processing can be added here as needed
    }
}
