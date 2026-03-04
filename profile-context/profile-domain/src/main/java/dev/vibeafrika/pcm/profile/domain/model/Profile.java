package dev.vibeafrika.pcm.profile.domain.model;

import dev.vibeafrika.pcm.profile.domain.exception.ProfileDeletedException;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Profile aggregate root - pure domain model.
 * No framework annotations, no persistence concerns.
 * 
 * Represents a user's profile with GDPR erasure support, versioning,
 * and dynamic attributes.
 */
public class Profile {
    private final ProfileId id;
    private final TenantId tenantId;
    private Handle handle;
    private Map<String, Object> attributes;
    private Instant createdAt;
    private Instant updatedAt;
    private Long version;
    private boolean deleted;

    /**
     * Private constructor - use factory methods.
     */
    private Profile(ProfileId id, TenantId tenantId, Handle handle, Map<String, Object> attributes) {
        this.id = Objects.requireNonNull(id, "Profile ID cannot be null");
        this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID cannot be null");
        this.handle = Objects.requireNonNull(handle, "Handle cannot be null");
        this.attributes = new HashMap<>(attributes != null ? attributes : Map.of());
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
        this.version = 0L;
        this.deleted = false;
    }

    /**
     * Factory method to create a new Profile.
     * 
     * @param tenantId The tenant identifier
     * @param handle The unique handle
     * @param attributes Initial attributes (can be null)
     * @return A new Profile instance
     */
    public static Profile create(TenantId tenantId, Handle handle, Map<String, Object> attributes) {
        return new Profile(ProfileId.generate(), tenantId, handle, attributes);
    }

    /**
     * Reconstitute a Profile from persistence.
     * Used by infrastructure layer to rebuild domain entities.
     * 
     * @param id The profile ID
     * @param tenantId The tenant ID
     * @param handle The handle
     * @param attributes The attributes map
     * @param createdAt Creation timestamp
     * @param updatedAt Last update timestamp
     * @param version Optimistic locking version
     * @param deleted Deletion flag
     * @return Reconstituted Profile instance
     */
    public static Profile reconstitute(ProfileId id, TenantId tenantId, Handle handle,
                                       Map<String, Object> attributes, Instant createdAt,
                                       Instant updatedAt, Long version, boolean deleted) {
        Profile profile = new Profile(id, tenantId, handle, attributes);
        profile.createdAt = createdAt;
        profile.updatedAt = updatedAt;
        profile.version = version;
        profile.deleted = deleted;
        return profile;
    }

    /**
     * Update profile attributes - enforces business rules.
     * 
     * @param newAttributes Attributes to add or update
     * @throws ProfileDeletedException if profile is deleted
     */
    public void updateAttributes(Map<String, Object> newAttributes) {
        if (this.deleted) {
            throw new ProfileDeletedException("Cannot update deleted profile");
        }
        if (newAttributes != null) {
            this.attributes.putAll(newAttributes);
            this.updatedAt = Instant.now();
        }
    }

    /**
     * Soft delete (GDPR erasure).
     * Clears all attributes and anonymizes the handle.
     */
    public void erase() {
        this.deleted = true;
        this.attributes.clear();
        this.handle = Handle.anonymized();
        this.updatedAt = Instant.now();
    }

    /**
     * Activate the profile.
     */
    public void activate() {
        if (this.deleted) {
            throw new ProfileDeletedException("Cannot activate deleted profile");
        }
        // Additional activation logic can be added here
        this.updatedAt = Instant.now();
    }

    /**
     * Deactivate the profile.
     */
    public void deactivate() {
        if (this.deleted) {
            throw new ProfileDeletedException("Cannot deactivate deleted profile");
        }
        // Additional deactivation logic can be added here
        this.updatedAt = Instant.now();
    }

    // Getters
    public ProfileId getId() {
        return id;
    }

    public TenantId getTenantId() {
        return tenantId;
    }

    public Handle getHandle() {
        return handle;
    }

    public Map<String, Object> getAttributes() {
        return new HashMap<>(attributes);
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Long getVersion() {
        return version;
    }

    public boolean isDeleted() {
        return deleted;
    }

    public boolean isActive() {
        return !deleted;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Profile)) return false;
        Profile profile = (Profile) o;
        return id.equals(profile.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "Profile{" +
                "id=" + id +
                ", tenantId=" + tenantId +
                ", handle=" + handle +
                ", deleted=" + deleted +
                '}';
    }
}
