package dev.vibeafrika.pcm.segment.domain.model;

import io.github.sympol.pure.asserts.Assert;
import java.util.*;

/**
 * SegmentCriteria value object - represents criteria for segment evaluation.
 * Contains rules for determining if a profile belongs to a segment.
 */
public final class SegmentCriteria {
    private final String criteriaType;
    private final Map<String, Object> parameters;

    private SegmentCriteria(String criteriaType, Map<String, Object> parameters) {
        this.criteriaType = Assert.field("criteriaType", criteriaType)
            .notBlank()
            .maxLength(50)
            .value();
        this.parameters = new HashMap<>(parameters != null ? parameters : Map.of());
    }

    /**
     * Create criteria with type and parameters.
     */
    public static SegmentCriteria of(String criteriaType, Map<String, Object> parameters) {
        return new SegmentCriteria(criteriaType, parameters);
    }

    /**
     * Create criteria with type only (no parameters).
     */
    public static SegmentCriteria of(String criteriaType) {
        return new SegmentCriteria(criteriaType, Map.of());
    }

    /**
     * Create tag-based criteria.
     */
    public static SegmentCriteria tagBased(String tag) {
        Assert.field("tag", tag).notBlank();
        return new SegmentCriteria("TAG", Map.of("tag", tag));
    }

    /**
     * Create score-based criteria.
     */
    public static SegmentCriteria scoreBased(String scoreKey, double minValue, double maxValue) {
        Assert.field("scoreKey", scoreKey).notBlank();
        
        // Validate score ranges manually
        if (minValue < 0.0 || minValue > 1.0) {
            throw new IllegalArgumentException("minValue must be between 0.0 and 1.0");
        }
        if (maxValue < 0.0 || maxValue > 1.0) {
            throw new IllegalArgumentException("maxValue must be between 0.0 and 1.0");
        }
        if (minValue > maxValue) {
            throw new IllegalArgumentException("minValue cannot be greater than maxValue");
        }
        
        return new SegmentCriteria("SCORE", Map.of(
            "scoreKey", scoreKey,
            "minValue", minValue,
            "maxValue", maxValue
        ));
    }

    /**
     * Create attribute-based criteria.
     */
    public static SegmentCriteria attributeBased(String attributeKey, Object attributeValue) {
        Assert.field("attributeKey", attributeKey).notBlank();
        
        // Validate attribute value is not null
        if (attributeValue == null) {
            throw new IllegalArgumentException("attributeValue cannot be null");
        }
        
        return new SegmentCriteria("ATTRIBUTE", Map.of(
            "attributeKey", attributeKey,
            "attributeValue", attributeValue
        ));
    }

    public String getCriteriaType() {
        return criteriaType;
    }

    public Map<String, Object> getParameters() {
        return new HashMap<>(parameters);
    }

    public Object getParameter(String key) {
        return parameters.get(key);
    }

    public boolean hasParameter(String key) {
        return parameters.containsKey(key);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SegmentCriteria)) return false;
        SegmentCriteria that = (SegmentCriteria) o;
        return criteriaType.equals(that.criteriaType) && 
               parameters.equals(that.parameters);
    }

    @Override
    public int hashCode() {
        return Objects.hash(criteriaType, parameters);
    }

    @Override
    public String toString() {
        return "SegmentCriteria{" +
                "type='" + criteriaType + '\'' +
                ", parameters=" + parameters +
                '}';
    }
}
