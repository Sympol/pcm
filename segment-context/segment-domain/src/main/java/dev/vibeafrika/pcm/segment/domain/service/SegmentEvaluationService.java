package dev.vibeafrika.pcm.segment.domain.service;

import dev.vibeafrika.pcm.segment.domain.model.Segment;

import java.util.Map;

/**
 * Domain service for evaluating segment rules.
 */
public class SegmentEvaluationService {

    /**
     * Evaluates a segment based on profile attributes and preferences.
     * @param segment the segment to evaluate
     * @param attributes the profile attributes
     * @param preferences the user preferences/settings
     * @return true if the segment state was changed
     */
    public boolean evaluate(Segment segment, Map<String, Object> attributes, Map<String, Object> preferences) {
        boolean changed = false;

        // Example logic 1: Tagging high-value users
        if (attributes.containsKey("total_spend")) {
            Object spendObj = attributes.get("total_spend");
            if (spendObj instanceof Number spend && spend.doubleValue() > 1000) {
                if (!segment.getTags().contains("high-value")) {
                    segment.getTags().add("high-value");
                    changed = true;
                }
            }
        }

        // Example logic 2: Scoring engagement based on preferences
        if (preferences.containsKey("newsletter_enabled") && Boolean.TRUE.equals(preferences.get("newsletter_enabled"))) {
            Double currentScore = segment.getScores().getOrDefault("engagement", 0.0);
            if (currentScore < 50.0) {
                segment.getScores().put("engagement", 50.0);
                changed = true;
            }
        }

        return changed;
    }
}
