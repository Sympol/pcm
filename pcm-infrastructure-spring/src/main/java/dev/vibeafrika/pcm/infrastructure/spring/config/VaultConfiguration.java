package dev.vibeafrika.pcm.infrastructure.spring.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;

import java.net.URI;

/**
 * Spring configuration for HashiCorp Vault connectivity.
 *
 * <p>Activated when {@code pcm.encryption.kms.provider=VAULT}.
 * Reads connection parameters from standard Vault environment variables:
 * <ul>
 *   <li>{@code VAULT_ADDR} — Vault server address (e.g. {@code http://vault:8200})</li>
 *   <li>{@code VAULT_TOKEN} — Vault token with transit + kv policy</li>
 * </ul>
 *
 * <p>For production, replace token authentication with AppRole or Kubernetes auth.
 */
@Configuration
@ConditionalOnProperty(name = "pcm.encryption.kms.provider", havingValue = "VAULT")
public class VaultConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(VaultConfiguration.class);

    @Value("${VAULT_ADDR:http://localhost:8200}")
    private String vaultAddr;

    @Value("${VAULT_TOKEN:}")
    private String vaultToken;

    /**
     * Creates a {@link VaultTemplate} connected to the configured Vault instance.
     *
     * <p>Uses token-based authentication. For production deployments, consider
     * replacing this with AppRole ({@code VaultAppRoleAuthentication}) or
     * Kubernetes auth ({@code KubernetesAuthentication}) for better security posture.
     *
     * @return the configured VaultTemplate
     * @throws IllegalStateException if VAULT_TOKEN is not set
     */
    @Bean
    public VaultTemplate vaultTemplate() {
        if (vaultToken == null || vaultToken.isBlank()) {
            throw new IllegalStateException(
                    "VAULT_TOKEN environment variable is required when pcm.encryption.kms.provider=VAULT. "
                    + "Set it to a Vault token with transit read/write/encrypt/decrypt policy.");
        }

        VaultEndpoint endpoint = VaultEndpoint.from(URI.create(vaultAddr));
        VaultTemplate template = new VaultTemplate(endpoint, new TokenAuthentication(vaultToken));

        logger.info("VaultTemplate configured: addr={}", vaultAddr);
        return template;
    }
}
