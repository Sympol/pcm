package dev.vibeafrika.pcm.preference.domain.model;

import dev.vibeafrika.pcm.preference.domain.exception.PreferenceDeletedException;
import dev.vibeafrika.pcm.preference.domain.exception.PreferenceValidationException;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Preference aggregate root - pure domain model.
 * Represents user UX settings and preferences.
 * No framework annotations, no persistence concerns.
 */
public class Preference {
    private final PreferenceId id;
    private final TenantId tenantId;
    private final ProfileId profileId;
    private Map<String, String> settings;
    private Instant lastUpdated;
    private boolean deleted;

    // Private constructor - use factory methods
    private Preference(PreferenceId id, TenantId tenantId, ProfileId profileId, 
                      Map<String, String> settings) {
        this.id = requireNonNull(id, "Preference ID cannot be null");
        this.tenantId = requireNonNull(tenantId, "Tenant ID cannot be null");
        this.profileId = requireNonNull(profileId, "Profile ID cannot be null");
        this.settings = new HashMap<>(settings != null ? settings : Map.of());
        this.lastUpdated = Instant.now();
        this.deleted = false;
    }

    /**
     * Factory method to create a new Preference.
     */
    public static Preference create(TenantId tenantId, ProfileId profileId) {
        return new Preference(PreferenceId.generate(), tenantId, profileId, Map.of());
    }

    /**
     * Factory method to create a new Preference with initial settings.
     */
    public static Preference create(TenantId tenantId, ProfileId profileId, 
                                   Map<String, String> initialSettings) {
        return new Preference(PreferenceId.generate(), tenantId, profileId, initialSettings);
    }

    /**
     * Reconstitute a Preference from persistence.
     * Used by infrastructure layer to rebuild domain entity from database.
     */
    public static Preference reconstitute(PreferenceId id, TenantId tenantId, ProfileId profileId,
                                         Map<String, String> settings, Instant lastUpdated, 
                                         boolean deleted) {
        Preference preference = new Preference(id, tenantId, profileId, settings);
        preference.lastUpdated = lastUpdated;
        preference.deleted = deleted;
        return preference;
    }

    /**
     * Update multiple settings at once - enforces business rules.
     */
    public void updateSettings(Map<String, String> newSettings) {
        if (this.deleted) {
            throw new PreferenceDeletedException("Cannot update deleted preference");
        }
        if (newSettings == null || newSettings.isEmpty()) {
            throw new PreferenceValidationException("Settings cannot be null or empty");
        }
        
        // Validate all keys before updating
        for (String key : newSettings.keySet()) {
            validateSettingKey(key);
        }
        
        this.settings.putAll(newSettings);
        this.lastUpdated = Instant.now();
    }

    /**
     * Set a single setting - enforces business rules.
     */
    public void setSetting(PreferenceKey key, String value) {
        if (this.deleted) {
            throw new PreferenceDeletedException("Cannot update deleted preference");
        }
        if (key == null) {
            throw new PreferenceValidationException("Setting key cannot be null");
        }
        if (value == null) {
            throw new PreferenceValidationException("Setting value cannot be null");
        }
        
        this.settings.put(key.getValue(), value);
        this.lastUpdated = Instant.now();
    }

    /**
     * Get a setting value by key.
     */
    public String getSetting(PreferenceKey key) {
        if (key == null) {
            throw new PreferenceValidationException("Setting key cannot be null");
        }
        return settings.get(key.getValue());
    }

    /**
     * Remove a setting by key.
     */
    public void removeSetting(PreferenceKey key) {
        if (this.deleted) {
            throw new PreferenceDeletedException("Cannot update deleted preference");
        }
        if (key == null) {
            throw new PreferenceValidationException("Setting key cannot be null");
        }
        
        this.settings.remove(key.getValue());
        this.lastUpdated = Instant.now();
    }

    /**
     * Soft delete (mark as deleted).
     */
    public void delete() {
        this.deleted = true;
        this.lastUpdated = Instant.now();
    }

    /**
     * Validate the preference state.
     */
    public void validate() {
        if (this.id == null) {
            throw new PreferenceValidationException("Preference ID cannot be null");
        }
        if (this.tenantId == null) {
            throw new PreferenceValidationException("Tenant ID cannot be null");
        }
        if (this.profileId == null) {
            throw new PreferenceValidationException("Profile ID cannot be null");
        }
    }

    /**
     * Validate a setting key.
     */
    private void validateSettingKey(String key) {
        if (key == null || key.isBlank()) {
            throw new PreferenceValidationException("Setting key cannot be null or blank");
        }
        if (key.length() > 100) {
            throw new PreferenceValidationException("Setting key cannot exceed 100 characters");
        }
    }

    // Getters
    public PreferenceId getId() {
        return id;
    }

    public TenantId getTenantId() {
        return tenantId;
    }

    public ProfileId getProfileId() {
        return profileId;
    }

    public Map<String, String> getSettings() {
        return new HashMap<>(settings);
    }

    public Instant getLastUpdated() {
        return lastUpdated;
    }

    public boolean isDeleted() {
        return deleted;
    }

    public boolean isActive() {
        return !deleted;
    }

    // Helper method for null checking
    private static <T> T requireNonNull(T obj, String message) {
        if (obj == null) {
            throw new PreferenceValidationException(message);
        }
        return obj;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Preference)) return false;
        Preference that = (Preference) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "Preference{" +
                "id=" + id +
                ", tenantId=" + tenantId +
                ", profileId=" + profileId +
                ", settingsCount=" + settings.size() +
                ", lastUpdated=" + lastUpdated +
                ", deleted=" + deleted +
                '}';
    }
}
