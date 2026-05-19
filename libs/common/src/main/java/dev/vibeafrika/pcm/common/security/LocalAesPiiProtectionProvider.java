package dev.vibeafrika.pcm.common.security;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * A simple PII protection provider using local AES-GCM encryption.
 * Primarily intended for development or small-scale deployments without Vault.
 *
 * <p>Uses AES-128-GCM with a random 96-bit IV prepended to the ciphertext,
 * providing both confidentiality and authenticated integrity (AEAD).
 */
@Slf4j
public final class LocalAesPiiProtectionProvider implements PiiProtectionProvider {

    private static final String ALGORITHM    = "AES";
    private static final String CIPHER_SPEC  = "AES/GCM/NoPadding";
    private static final int    GCM_TAG_BITS = 128;
    private static final int    IV_BYTES     = 12;   // 96-bit IV recommended for GCM
    private static final String PREFIX       = "local:v2:";

    private final SecretKeySpec secretKey;
    private final SecureRandom  secureRandom = new SecureRandom();

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
            byte[] iv = new byte[IV_BYTES];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(CIPHER_SPEC);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // Prepend IV to ciphertext: [12 bytes IV][ciphertext + 16 bytes GCM tag]
            byte[] ivAndCipher = new byte[IV_BYTES + encrypted.length];
            System.arraycopy(iv, 0, ivAndCipher, 0, IV_BYTES);
            System.arraycopy(encrypted, 0, ivAndCipher, IV_BYTES, encrypted.length);

            return PREFIX + Base64.getEncoder().encodeToString(ivAndCipher);
        } catch (Exception e) {
            log.error("Error encrypting PII locally", e);
            throw new RuntimeException("Encryption failed", e);
        }
    }

    @Override
    public String decrypt(String cipherText) {
        if (cipherText == null || !cipherText.startsWith(PREFIX)) {
            return cipherText;
        }
        try {
            byte[] ivAndCipher = Base64.getDecoder().decode(cipherText.substring(PREFIX.length()));

            byte[] iv = new byte[IV_BYTES];
            System.arraycopy(ivAndCipher, 0, iv, 0, IV_BYTES);
            byte[] encrypted = new byte[ivAndCipher.length - IV_BYTES];
            System.arraycopy(ivAndCipher, IV_BYTES, encrypted, 0, encrypted.length);

            Cipher cipher = Cipher.getInstance(CIPHER_SPEC);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] decrypted = cipher.doFinal(encrypted);

            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("Error decrypting PII locally", e);
            throw new RuntimeException("Decryption failed", e);
        }
    }
}
