package dev.vibeafrika.pcm.preference.infrastructure.persistence.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * JPA persistence entity for Preference.
 * Contains all framework-specific annotations.
 * Separate from domain entity.
 * Uses table prefix "preference_" for modular monolith isolation.
 */
@Entity
@Table(name = "preference_preferences", indexes = {
    @Index(name = "idx_preference_tenant", columnList = "tenant_id"),
    @Index(name = "idx_preference_profile", columnList = "profile_id"),
    @Index(name = "idx_preference_tenant_profile", columnList = "tenant_id,profile_id")
})
@EntityListeners(AuditingEntityListener.class)
public class PreferenceJpaEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, length = 100)
    private String tenantId;

    @Column(name = "profile_id", nullable = false)
    private UUID profileId;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "preference_settings",
        joinColumns = @JoinColumn(name = "preference_id")
    )
    @MapKeyColumn(name = "setting_key", length = 100)
    @Column(name = "setting_value", length = 1000)
    private Map<String, String> settings = new HashMap<>();

    @Column(name = "last_updated", nullable = false)
    private Instant lastUpdated;

    @Column(name = "deleted", nullable = false)
    private boolean deleted = false;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    @Column(name = "version")
    private Long version;

    // Default constructor for JPA
    public PreferenceJpaEntity() {
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

    public Map<String, String> getSettings() {
        return settings;
    }

    public void setSettings(Map<String, String> settings) {
        this.settings = settings;
    }

    public Instant getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(Instant lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    public boolean isDeleted() {
        return deleted;
    }

    public void setDeleted(boolean deleted) {
        this.deleted = deleted;
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

    public Long getVersion() {
        return version;
    }

    public void setVersion(Long version) {
        this.version = version;
    }
}
