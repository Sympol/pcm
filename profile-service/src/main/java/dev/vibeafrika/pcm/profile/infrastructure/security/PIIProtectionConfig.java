package dev.vibeafrika.pcm.profile.infrastructure.security;

import dev.vibeafrika.pcm.common.security.LocalAesPiiProtectionProvider;
import dev.vibeafrika.pcm.common.security.PiiProtectionProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.core.VaultOperations;

@Configuration
@Slf4j
public class PIIProtectionConfig {

    @Bean
    @ConditionalOnProperty(name = "pcm.security.pii.provider", havingValue = "vault", matchIfMissing = true)
    public PiiProtectionProvider vaultPiiProtectionProvider(VaultOperations vaultOperations,
            @Value("${pcm.profile.vault.transit.key-name:pcm-pii-key}") String piiKeyName) {
        log.info("Configuring Vault as the PII Protection Provider");
        return new VaultTransitService(vaultOperations, piiKeyName);
    }

    @Bean
    @ConditionalOnProperty(name = "pcm.security.pii.provider", havingValue = "local")
    public PiiProtectionProvider localPiiProtectionProvider(
            @Value("${pcm.security.pii.local.secret:abcdefghijklmnop}") String secret) {
        log.info("Configuring Local AES as the PII Protection Provider");
        return new LocalAesPiiProtectionProvider(secret);
    }
}
