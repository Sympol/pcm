package dev.vibeafrika.pcm.domain.encryption;

import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * Value object representing an encrypted Data Encryption Key (DEK).
 * 
 * <p>The encrypted DEK is the result of encrypting a DEK with a KEK in the KMS.
 * It can be safely stored outside the KMS and transmitted over the network.
 * 
 * <p>The encrypted DEK contains:
 * <ul>
 *   <li>The encrypted key material (ciphertext)</li>
 *   <li>The KEK ID used for encryption</li>
 *   <li>KMS-specific metadata (algorithm, key version, etc.)</li>
 * </ul>
 */
public final class EncryptedDEK {
    
    private final byte[] ciphertext;
    private final UUID kekId;
    private final String kmsMetadata;
    
    private EncryptedDEK(byte[] ciphertext, UUID kekId, String kmsMetadata) {
        this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
        this.kekId = kekId;
        this.kmsMetadata = kmsMetadata;
    }
    
    /**
     * Creates an EncryptedDEK from ciphertext and KEK ID.
     * 
     * @param ciphertext the encrypted DEK bytes
     * @param kekId the UUID of the KEK used for encryption
     * @return a new EncryptedDEK instance
     */
    public static EncryptedDEK of(byte[] ciphertext, UUID kekId) {
        return of(ciphertext, kekId, null);
    }
    
    /**
     * Creates an EncryptedDEK from ciphertext, KEK ID, and KMS metadata.
     * 
     * @param ciphertext the encrypted DEK bytes
     * @param kekId the UUID of the KEK used for encryption
     * @param kmsMetadata optional KMS-specific metadata (algorithm, version, etc.)
     * @return a new EncryptedDEK instance
     */
    public static EncryptedDEK of(byte[] ciphertext, UUID kekId, String kmsMetadata) {
        Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
        Objects.requireNonNull(kekId, "KEK ID cannot be null");
        if (ciphertext.length == 0) {
            throw new IllegalArgumentException("Ciphertext cannot be empty");
        }
        return new EncryptedDEK(ciphertext, kekId, kmsMetadata);
    }
    
    /**
     * Returns a copy of the encrypted ciphertext bytes.
     */
    public byte[] getCiphertext() {
        return Arrays.copyOf(ciphertext, ciphertext.length);
    }
    
    /**
     * Returns the UUID of the KEK used to encrypt this DEK.
     */
    public UUID getKekId() {
        return kekId;
    }
    
    /**
     * Returns the KMS-specific metadata, or null if not present.
     */
    public String getKmsMetadata() {
        return kmsMetadata;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedDEK that = (EncryptedDEK) o;
        return Arrays.equals(ciphertext, that.ciphertext) &&
               Objects.equals(kekId, that.kekId) &&
               Objects.equals(kmsMetadata, that.kmsMetadata);
    }
    
    @Override
    public int hashCode() {
        int result = Objects.hash(kekId, kmsMetadata);
        result = 31 * result + Arrays.hashCode(ciphertext);
        return result;
    }
    
    @Override
    public String toString() {
        return "EncryptedDEK{" +
               "ciphertextLength=" + ciphertext.length +
               ", kekId=" + kekId +
               ", hasMetadata=" + (kmsMetadata != null) +
               '}';
    }
}
