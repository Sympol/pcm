package dev.vibeafrika.pcm.common.security;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * A simple PII protection provider using local AES encryption.
 * Primarily intended for development or small-scale deployments without Vault.
 */
@Slf4j
public class LocalAesPiiProtectionProvider implements PiiProtectionProvider {

    private final SecretKeySpec secretKey;
    private static final String ALGORITHM = "AES";

    public LocalAesPiiProtectionProvider(String secret) {
        if (secret == null || secret.length() != 16) {
            throw new IllegalArgumentException("Secret key must be 16 characters long for AES-128");
        }
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    }

    @Override
    public String encrypt(String plainText) {
        if (plainText == null || plainText.isEmpty()) {
            return plainText;
        }
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return "local:v1:" + Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            log.error("Error encrypting PII locally", e);
            throw new RuntimeException("Encryption failed", e);
        }
    }

    @Override
    public String decrypt(String cipherText) {
        if (cipherText == null || !cipherText.startsWith("local:v1:")) {
            return cipherText;
        }
        try {
            String base64Encrypted = cipherText.substring("local:v1:".length());
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(base64Encrypted));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Error decrypting PII locally", e);
            throw new RuntimeException("Decryption failed", e);
        }
    }
}
