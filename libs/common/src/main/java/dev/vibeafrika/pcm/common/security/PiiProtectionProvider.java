package dev.vibeafrika.pcm.common.security;

/**
 * Interface for protecting Personally Identifiable Information (PII).
 * This allows the platform to abstract the underlying encryption mechanism
 * (Vault, Cloud KMS, Local AES, etc.).
 */
public interface PiiProtectionProvider {

    /**
     * Encrypts a plaintext string.
     * 
     * @param plainText the string to encrypt
     * @return the encrypted ciphertext
     */
    String encrypt(String plainText);

    /**
     * Decrypts a ciphertext string.
     * 
     * @param cipherText the ciphertext to decrypt
     * @return the original plaintext
     */
    String decrypt(String cipherText);
}
