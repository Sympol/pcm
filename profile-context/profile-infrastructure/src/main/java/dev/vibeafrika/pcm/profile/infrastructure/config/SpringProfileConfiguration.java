package dev.vibeafrika.pcm.profile.infrastructure.config;

import dev.vibeafrika.pcm.profile.application.config.ProfileConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Spring implementation of ProfileConfiguration interface.
 */
@Component
@ConfigurationProperties(prefix = "profile")
public class SpringProfileConfiguration implements ProfileConfiguration {

    private int maxAttributesPerProfile = 100;
    private boolean versioningEnabled = true;
    private int deletedProfileRetentionDays = 90;

    @Override
    public int getMaxAttributesPerProfile() {
        return maxAttributesPerProfile;
    }

    @Override
    public boolean isVersioningEnabled() {
        return versioningEnabled;
    }

    @Override
    public int getDeletedProfileRetentionDays() {
        return deletedProfileRetentionDays;
    }

    public void setMaxAttributesPerProfile(int maxAttributesPerProfile) {
        this.maxAttributesPerProfile = maxAttributesPerProfile;
    }

    public void setVersioningEnabled(boolean versioningEnabled) {
        this.versioningEnabled = versioningEnabled;
    }

    public void setDeletedProfileRetentionDays(int deletedProfileRetentionDays) {
        this.deletedProfileRetentionDays = deletedProfileRetentionDays;
    }
}
