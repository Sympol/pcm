package dev.vibeafrika.pcm.profile.infrastructure.security;

import dev.vibeafrika.pcm.common.security.PiiProtectionProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.Ciphertext;
import org.springframework.vault.support.Plaintext;

/**
 * Service for interacting with Vault's Transit secrets engine.
 * Provides transparent encryption and decryption for sensitive user data.
 */
@Service
public class VaultTransitService implements PiiProtectionProvider {

    private final VaultOperations vaultOperations;
    private final String piiKeyName;

    public VaultTransitService(VaultOperations vaultOperations,
            @Value("${pcm.profile.vault.transit.key-name:pcm-pii-key}") String piiKeyName) {
        this.vaultOperations = vaultOperations;
        this.piiKeyName = piiKeyName;
    }

    /**
     * Encrypts plaintext string using the Transit engine.
     * Returns ciphertext in the format vault:v1:...
     */
    public String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            return plaintext;
        }
        return vaultOperations.opsForTransit()
                .encrypt(piiKeyName, Plaintext.of(plaintext))
                .getCiphertext();
    }

    /**
     * Decrypts ciphertext (vault:v1:...) back to plaintext string.
     */
    public String decrypt(String ciphertext) {
        if (ciphertext == null || !ciphertext.startsWith("vault:")) {
            return ciphertext;
        }
        return vaultOperations.opsForTransit()
                .decrypt(piiKeyName, Ciphertext.of(ciphertext))
                .asString();
    }
}
