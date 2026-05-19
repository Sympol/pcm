package dev.vibeafrika.pcm.segment.domain.model;

import dev.vibeafrika.pcm.segment.domain.exception.SegmentValidationException;

import java.time.Instant;
import java.util.*;

/**
 * Segment aggregate root - pure domain model.
 * Represents a user's classification and behavioral scores.
 */
public final class Segment {
    private final SegmentId id;
    private final TenantId tenantId;
    private final ProfileId profileId;
    private Set<String> tags;
    private Map<String, Double> scores;
    private Instant lastUpdated;

    // Private constructor - use factory methods
    private Segment(SegmentId id, TenantId tenantId, ProfileId profileId) {
        this.id = requireNonNull(id, "Segment ID cannot be null");
        this.tenantId = requireNonNull(tenantId, "Tenant ID cannot be null");
        this.profileId = requireNonNull(profileId, "Profile ID cannot be null");
        this.tags = new HashSet<>();
        this.scores = new HashMap<>();
        this.lastUpdated = Instant.now();
    }

    /**
     * Factory method to create a new Segment.
     */
    public static Segment create(TenantId tenantId, ProfileId profileId) {
        return new Segment(SegmentId.generate(), tenantId, profileId);
    }

    /**
     * Factory method to create a new Segment with initial tags and scores.
     */
    public static Segment create(TenantId tenantId, ProfileId profileId, 
                                Set<String> initialTags, Map<String, Double> initialScores) {
        Segment segment = new Segment(SegmentId.generate(), tenantId, profileId);
        if (initialTags != null) {
            segment.tags = new HashSet<>(initialTags);
        }
        if (initialScores != null) {
            segment.scores = new HashMap<>(initialScores);
        }
        return segment;
    }

    /**
     * Reconstitute a Segment from persistence.
     * Used by infrastructure layer to rebuild domain entity from database.
     */
    public static Segment reconstitute(SegmentId id, TenantId tenantId, ProfileId profileId,
                                      Set<String> tags, Map<String, Double> scores, 
                                      Instant lastUpdated) {
        Segment segment = new Segment(id, tenantId, profileId);
        segment.tags = new HashSet<>(tags != null ? tags : Set.of());
        segment.scores = new HashMap<>(scores != null ? scores : Map.of());
        segment.lastUpdated = lastUpdated;
        return segment;
    }

    /**
     * Update segments with new tags and scores - enforces business rules.
     */
    public void updateSegments(Set<String> newTags, Map<String, Double> newScores) {
        if (newTags == null && newScores == null) {
            throw new SegmentValidationException("At least one of tags or scores must be provided");
        }
        
        if (newTags != null) {
            validateTags(newTags);
            this.tags = new HashSet<>(newTags);
        }
        
        if (newScores != null) {
            validateScores(newScores);
            this.scores = new HashMap<>(newScores);
        }
        
        this.lastUpdated = Instant.now();
    }

    /**
     * Add a tag to the segment.
     */
    public void addTag(String tag) {
        validateTag(tag);
        this.tags.add(tag);
        this.lastUpdated = Instant.now();
    }

    /**
     * Remove a tag from the segment.
     */
    public void removeTag(String tag) {
        if (tag == null || tag.isBlank()) {
            throw new SegmentValidationException("Tag cannot be null or blank");
        }
        this.tags.remove(tag);
        this.lastUpdated = Instant.now();
    }

    /**
     * Set a score value.
     */
    public void setScore(String key, Double value) {
        validateScoreKey(key);
        validateScoreValue(value);
        this.scores.put(key, value);
        this.lastUpdated = Instant.now();
    }

    /**
     * Remove a score.
     */
    public void removeScore(String key) {
        if (key == null || key.isBlank()) {
            throw new SegmentValidationException("Score key cannot be null or blank");
        }
        this.scores.remove(key);
        this.lastUpdated = Instant.now();
    }

    /**
     * Get a score value by key.
     */
    public Double getScore(String key) {
        if (key == null || key.isBlank()) {
            throw new SegmentValidationException("Score key cannot be null or blank");
        }
        return scores.get(key);
    }

    /**
     * Check if segment has a specific tag.
     */
    public boolean hasTag(String tag) {
        return tags.contains(tag);
    }

    /**
     * Validate the segment state.
     */
    public void validate() {
        if (this.id == null) {
            throw new SegmentValidationException("Segment ID cannot be null");
        }
        if (this.tenantId == null) {
            throw new SegmentValidationException("Tenant ID cannot be null");
        }
        if (this.profileId == null) {
            throw new SegmentValidationException("Profile ID cannot be null");
        }
    }

    /**
     * Validate tags collection.
     */
    private void validateTags(Set<String> tags) {
        if (tags == null) {
            return;
        }
        for (String tag : tags) {
            validateTag(tag);
        }
    }

    /**
     * Validate a single tag.
     */
    private void validateTag(String tag) {
        if (tag == null || tag.isBlank()) {
            throw new SegmentValidationException("Tag cannot be null or blank");
        }
        if (tag.length() > 100) {
            throw new SegmentValidationException("Tag cannot exceed 100 characters");
        }
    }

    /**
     * Validate scores map.
     */
    private void validateScores(Map<String, Double> scores) {
        if (scores == null) {
            return;
        }
        for (Map.Entry<String, Double> entry : scores.entrySet()) {
            validateScoreKey(entry.getKey());
            validateScoreValue(entry.getValue());
        }
    }

    /**
     * Validate a score key.
     */
    private void validateScoreKey(String key) {
        if (key == null || key.isBlank()) {
            throw new SegmentValidationException("Score key cannot be null or blank");
        }
        if (key.length() > 100) {
            throw new SegmentValidationException("Score key cannot exceed 100 characters");
        }
    }

    /**
     * Validate a score value.
     */
    private void validateScoreValue(Double value) {
        if (value == null) {
            throw new SegmentValidationException("Score value cannot be null");
        }
        if (value < 0.0 || value > 1.0) {
            throw new SegmentValidationException("Score value must be between 0.0 and 1.0");
        }
    }

    // Getters
    public SegmentId getId() {
        return id;
    }

    public TenantId getTenantId() {
        return tenantId;
    }

    public ProfileId getProfileId() {
        return profileId;
    }

    public Set<String> getTags() {
        return new HashSet<>(tags);
    }

    public Map<String, Double> getScores() {
        return new HashMap<>(scores);
    }

    public Instant getLastUpdated() {
        return lastUpdated;
    }

    // Helper method for null checking
    private static <T> T requireNonNull(T obj, String message) {
        if (obj == null) {
            throw new SegmentValidationException(message);
        }
        return obj;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Segment)) return false;
        Segment segment = (Segment) o;
        return Objects.equals(id, segment.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "Segment{" +
                "id=" + id +
                ", tenantId=" + tenantId +
                ", profileId=" + profileId +
                ", tagsCount=" + tags.size() +
                ", scoresCount=" + scores.size() +
                ", lastUpdated=" + lastUpdated +
                '}';
    }
}
