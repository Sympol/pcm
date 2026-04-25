package dev.vibeafrika.pcm.domain.encryption;

import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Domain value object that maintains the version compatibility matrix for
 * encryption algorithms.
 *
 * <p>Records which algorithms can decrypt ciphertext produced by which other
 * algorithms. This is essential during migrations: a new algorithm may need
 * to decrypt data originally encrypted by an older algorithm.
 *
 * <p>Pre-populated compatibility rules:
 * <ul>
 *   <li>{@code AES_256_GCM} can decrypt {@code AES_256_GCM} ciphertext</li>
 *   <li>{@code AES_256_CBC_HMAC} can decrypt {@code AES_256_CBC_HMAC} ciphertext</li>
 *   <li>{@code AES_256_GCM} can also decrypt {@code AES_256_CBC_HMAC} ciphertext
 *       (migration compatibility, Req 32.6)</li>
 * </ul>
 */
public class AlgorithmCompatibilityMatrix {

    /**
     * Maps an encrypting algorithm to the set of algorithms that can decrypt its output.
     * Key = algorithm that produced the ciphertext.
     * Value = set of algorithms capable of decrypting that ciphertext.
     */
    private final Map<EncryptionAlgorithm, Set<EncryptionAlgorithm>> matrix;

    /**
     * Creates a new matrix pre-populated with the default compatibility rules.
     */
    public AlgorithmCompatibilityMatrix() {
        this.matrix = new ConcurrentHashMap<>();
        populateDefaults();
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Registers that {@code decryptingAlgorithm} is capable of decrypting
     * ciphertext produced by {@code encryptingAlgorithm}.
     *
     * @param encryptingAlgorithm the algorithm that produced the ciphertext
     * @param decryptingAlgorithm the algorithm that can decrypt it
     */
    public void register(EncryptionAlgorithm encryptingAlgorithm,
                         EncryptionAlgorithm decryptingAlgorithm) {
        Objects.requireNonNull(encryptingAlgorithm, "encryptingAlgorithm cannot be null");
        Objects.requireNonNull(decryptingAlgorithm, "decryptingAlgorithm cannot be null");

        matrix.computeIfAbsent(encryptingAlgorithm,
                k -> Collections.synchronizedSet(EnumSet.noneOf(EncryptionAlgorithm.class)))
              .add(decryptingAlgorithm);
    }

    /**
     * Returns {@code true} if {@code decryptingAlgorithm} can decrypt ciphertext
     * that was produced by {@code encryptingAlgorithm}.
     *
     * @param encryptingAlgorithm the algorithm that produced the ciphertext
     * @param decryptingAlgorithm the algorithm to test for compatibility
     * @return {@code true} if compatible
     */
    public boolean canDecrypt(EncryptionAlgorithm encryptingAlgorithm,
                              EncryptionAlgorithm decryptingAlgorithm) {
        Objects.requireNonNull(encryptingAlgorithm, "encryptingAlgorithm cannot be null");
        Objects.requireNonNull(decryptingAlgorithm, "decryptingAlgorithm cannot be null");

        Set<EncryptionAlgorithm> decryptors = matrix.get(encryptingAlgorithm);
        return decryptors != null && decryptors.contains(decryptingAlgorithm);
    }

    /**
     * Returns the set of algorithms that can decrypt ciphertext produced by
     * {@code encryptingAlgorithm}.
     *
     * @param encryptingAlgorithm the algorithm that produced the ciphertext
     * @return an unmodifiable set of compatible decryptors (may be empty)
     */
    public Set<EncryptionAlgorithm> getCompatibleDecryptors(EncryptionAlgorithm encryptingAlgorithm) {
        Objects.requireNonNull(encryptingAlgorithm, "encryptingAlgorithm cannot be null");

        Set<EncryptionAlgorithm> decryptors = matrix.get(encryptingAlgorithm);
        if (decryptors == null) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(decryptors);
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /**
     * Pre-populates the matrix with the default compatibility rules.
     */
    private void populateDefaults() {
        // Each algorithm can decrypt its own ciphertext
        register(EncryptionAlgorithm.AES_256_GCM, EncryptionAlgorithm.AES_256_GCM);
        register(EncryptionAlgorithm.AES_256_CBC_HMAC, EncryptionAlgorithm.AES_256_CBC_HMAC);

        // Migration compatibility: AES_256_GCM can decrypt AES_256_CBC_HMAC ciphertext
        // to support migrating data from AES_256_CBC_HMAC to AES_256_GCM (Req 32.6)
        register(EncryptionAlgorithm.AES_256_CBC_HMAC, EncryptionAlgorithm.AES_256_GCM);
    }
}
