package dev.vibeafrika.pcm.profile.domain.model;

import dev.vibeafrika.pcm.common.domain.TenantId;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Profile aggregate root - represents a user's profile in the system.
 * This is the main entity in the Profile bounded context.
 */
@Entity
@Table(name = "profiles", indexes = {
        @Index(name = "idx_profile_tenant", columnList = "tenant_id"),
        @Index(name = "idx_profile_handle", columnList = "handle", unique = true)
})
@SQLDelete(sql = "UPDATE profiles SET deleted_at = NOW() WHERE id = ?")
@SQLRestriction("deleted_at IS NULL")
@EntityListeners(AuditingEntityListener.class)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Profile {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, length = 100)
    private String tenantId;

    @Embedded
    private Handle handle;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "attributes")
    private Map<String, Object> attributes = new HashMap<>();

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    @Column(name = "version")
    private Long version;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    /**
     * Factory method to create a new Profile with random ID.
     */
    public static Profile create(TenantId tenantId, Handle handle, Map<String, Object> attributes) {
        return createWithId(UUID.randomUUID(), tenantId, handle, attributes);
    }

    /**
     * Factory method to create a new Profile with a specific ID.
     */
    public static Profile createWithId(UUID id, TenantId tenantId, Handle handle, Map<String, Object> attributes) {
        Profile profile = new Profile();
        profile.id = id;
        profile.tenantId = tenantId.getValue();
        profile.handle = handle;
        profile.attributes = attributes != null ? new HashMap<>(attributes) : new HashMap<>();
        return profile;
    }

    /**
     * Update profile attributes.
     */
    public void updateAttributes(Map<String, Object> newAttributes) {
        if (this.deletedAt != null) {
            throw new IllegalStateException("Cannot update deleted profile");
        }
        if (newAttributes != null) {
            this.attributes.putAll(newAttributes);
        }
    }

    /**
     * Soft delete the profile (GDPR erasure).
     */
    public void erase() {
        this.deletedAt = Instant.now();
        this.attributes.clear();
        this.handle = Handle.anonymized();
    }

    /**
     * Get a specific attribute value.
     */
    public Object getAttribute(String key) {
        return attributes.get(key);
    }

    /**
     * Set a specific attribute.
     */
    public void setAttribute(String key, Object value) {
        if (this.deletedAt != null) {
            throw new IllegalStateException("Cannot modify deleted profile");
        }
        this.attributes.put(key, value);
    }

    /**
     * Check if profile is active (not deleted).
     */
    public boolean isActive() {
        return deletedAt == null;
    }
}
