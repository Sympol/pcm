package dev.vibeafrika.pcm.preference.infrastructure.config;

import dev.vibeafrika.pcm.preference.application.config.PreferenceConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Spring implementation of PreferenceConfiguration interface.
 * Loads configuration from application.yml with prefix "preference".
 */
@Component
@ConfigurationProperties(prefix = "preference")
public class SpringPreferenceConfiguration implements PreferenceConfiguration {

    private int maxSettingsPerPreference = 100;
    private boolean cachingEnabled = true;
    private int cacheTtlSeconds = 300;
    private boolean versioningEnabled = true;
    private int deletedPreferenceRetentionDays = 30;

    @Override
    public int getMaxSettingsPerPreference() {
        return maxSettingsPerPreference;
    }

    @Override
    public boolean isCachingEnabled() {
        return cachingEnabled;
    }

    @Override
    public int getCacheTtlSeconds() {
        return cacheTtlSeconds;
    }

    @Override
    public boolean isVersioningEnabled() {
        return versioningEnabled;
    }

    @Override
    public int getDeletedPreferenceRetentionDays() {
        return deletedPreferenceRetentionDays;
    }

    // Setters for Spring to inject values
    public void setMaxSettingsPerPreference(int maxSettingsPerPreference) {
        this.maxSettingsPerPreference = maxSettingsPerPreference;
    }

    public void setCachingEnabled(boolean cachingEnabled) {
        this.cachingEnabled = cachingEnabled;
    }

    public void setCacheTtlSeconds(int cacheTtlSeconds) {
        this.cacheTtlSeconds = cacheTtlSeconds;
    }

    public void setVersioningEnabled(boolean versioningEnabled) {
        this.versioningEnabled = versioningEnabled;
    }

    public void setDeletedPreferenceRetentionDays(int deletedPreferenceRetentionDays) {
        this.deletedPreferenceRetentionDays = deletedPreferenceRetentionDays;
    }
}
