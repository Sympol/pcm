package dev.vibeafrika.pcm.segment.infrastructure.persistence.entity;

import dev.vibeafrika.pcm.segment.infrastructure.persistence.listener.SegmentEncryptionEntityListener;
import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * JPA persistence entity for Segment.
 * Contains all framework-specific annotations.
 * Separate from domain entity.
 * Uses table prefix "segment_" for modular monolith isolation.
 */
@Entity
@Table(name = "segment_segments", indexes = {
    @Index(name = "idx_segment_tenant", columnList = "tenant_id"),
    @Index(name = "idx_segment_profile", columnList = "profile_id"),
    @Index(name = "idx_segment_tenant_profile", columnList = "tenant_id,profile_id")
})
@EntityListeners({AuditingEntityListener.class, SegmentEncryptionEntityListener.class})
public class SegmentJpaEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, length = 100)
    private String tenantId;

    @Column(name = "profile_id", nullable = false)
    private UUID profileId;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "segment_tags",
        joinColumns = @JoinColumn(name = "segment_id")
    )
    @Column(name = "tag", length = 100)
    private Set<String> tags = new HashSet<>();

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "scores", columnDefinition = "jsonb")
    private Map<String, Double> scores = new HashMap<>();

    @Column(name = "last_updated", nullable = false)
    private Instant lastUpdated;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    // Default constructor for JPA
    public SegmentJpaEntity() {
    }

    // Getters and setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public UUID getProfileId() {
        return profileId;
    }

    public void setProfileId(UUID profileId) {
        this.profileId = profileId;
    }

    public Set<String> getTags() {
        return tags;
    }

    public void setTags(Set<String> tags) {
        this.tags = tags;
    }

    public Map<String, Double> getScores() {
        return scores;
    }

    public void setScores(Map<String, Double> scores) {
        this.scores = scores;
    }

    public Instant getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(Instant lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
