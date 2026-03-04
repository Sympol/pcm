package dev.vibeafrika.pcm.consent.infrastructure.config;

import dev.vibeafrika.pcm.consent.application.config.ConsentConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "consent")
public class SpringConsentConfiguration implements ConsentConfiguration {

    private int consentRetentionYears = 7;
    private boolean enableTcfIntegration = true;

    @Override
    public int getConsentRetentionYears() {
        return consentRetentionYears;
    }

    @Override
    public boolean isEnableTCFIntegration() {
        return enableTcfIntegration;
    }

    public void setConsentRetentionYears(int consentRetentionYears) {
        this.consentRetentionYears = consentRetentionYears;
    }

    public void setEnableTCFIntegration(boolean enableTcfIntegration) {
        this.enableTcfIntegration = enableTcfIntegration;
    }
}
