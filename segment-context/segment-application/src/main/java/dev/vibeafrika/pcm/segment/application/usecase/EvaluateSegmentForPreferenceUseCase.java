package dev.vibeafrika.pcm.segment.application.usecase;

import dev.vibeafrika.pcm.segment.application.port.EventPublisher;
import dev.vibeafrika.pcm.segment.application.port.PreferenceProvider;
import dev.vibeafrika.pcm.segment.application.port.ProfileProvider;
import dev.vibeafrika.pcm.segment.domain.event.SegmentUpdatedEvent;
import dev.vibeafrika.pcm.segment.domain.model.ProfileId;
import dev.vibeafrika.pcm.segment.domain.model.Segment;
import dev.vibeafrika.pcm.segment.domain.model.TenantId;
import dev.vibeafrika.pcm.segment.domain.repository.SegmentRepository;
import dev.vibeafrika.pcm.segment.domain.service.SegmentEvaluationService;

import java.util.List;
import java.util.UUID;

/**
 * Use case for evaluating segments when a preference is created or updated.
 */
public class EvaluateSegmentForPreferenceUseCase {
    private final SegmentRepository segmentRepository;
    private final ProfileProvider profileProvider;
    private final PreferenceProvider preferenceProvider;
    private final EventPublisher eventPublisher;
    private final SegmentEvaluationService evaluationService;

    public EvaluateSegmentForPreferenceUseCase(
            SegmentRepository segmentRepository,
            ProfileProvider profileProvider,
            PreferenceProvider preferenceProvider,
            EventPublisher eventPublisher,
            SegmentEvaluationService evaluationService) {
        this.segmentRepository = segmentRepository;
        this.profileProvider = profileProvider;
        this.preferenceProvider = preferenceProvider;
        this.eventPublisher = eventPublisher;
        this.evaluationService = evaluationService;
    }

    public void execute(UUID profileId, String tenantId) {
        // 1. Find segments for this profile
        ProfileId domainProfileId = ProfileId.of(profileId);
        TenantId domainTenantId = TenantId.of(tenantId);
        List<Segment> segments = segmentRepository.findByProfile(domainProfileId, domainTenantId);

        // 2. Fetch profile data (Snapshot)
        var profileOpt = profileProvider.getProfileSnapshot(profileId);
        if (profileOpt.isEmpty()) return;

        // 3. Fetch preferences
        var preferences = preferenceProvider.getPreferences(profileId, tenantId);

        // 4. Evaluate each segment
        for (Segment segment : segments) {
            boolean changed = evaluationService.evaluate(segment, profileOpt.get().attributes(), preferences);
            
            if (changed) {
                // 5. Persist
                Segment savedSegment = segmentRepository.save(segment);

                // 6. Publish domain event
                eventPublisher.publish(SegmentUpdatedEvent.of(
                        savedSegment.getId(),
                        savedSegment.getProfileId(),
                        savedSegment.getTenantId(),
                        savedSegment.getTags(),
                        savedSegment.getScores()
                ));
            }
        }
    }
}
