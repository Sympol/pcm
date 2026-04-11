package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Service for generating blind indexes for searchable encryption.
 *
 * <p>Blind indexes enable exact-match searching on encrypted fields while
 * resisting frequency analysis and pattern matching attacks.
 *
 * <p>Algorithm:
 * <pre>
 * blind_index = HMAC-SHA256(
 *   key: blind_index_key,
 *   message: global_salt || per_record_salt || normalized_plaintext
 * )
 * </pre>
 *
 * <p>Where normalization = lowercase + trim.
 *
 * <p>Side-channel protection: HMAC verification uses {@link ConstantTime#verifyHmac}
 * to prevent timing attacks. The JDK's {@code HmacSHA256} implementation runs in
 * constant time for the MAC computation itself; the comparison is also constant-time.
 *
 * <p>Note on cache-timing attacks: the HMAC key material is accessed through a
 * fixed-size byte array. Callers should avoid branching on the blind index value
 * to prevent cache-timing leakage.
 */
public class BlindIndexService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final IKeyManager keyManager;
    private final String globalSalt;

    /**
     * Creates a BlindIndexService with the given key manager and global salt.
     *
     * @param keyManager the key manager used to retrieve the blind index key
     * @param globalSalt a secret global salt shared across all records (resists frequency analysis)
     */
    public BlindIndexService(IKeyManager keyManager, String globalSalt) {
        this.keyManager = Objects.requireNonNull(keyManager, "KeyManager cannot be null");
        Objects.requireNonNull(globalSalt, "Global salt cannot be null");
        if (globalSalt.isEmpty()) {
            throw new IllegalArgumentException("Global salt cannot be empty");
        }
        this.globalSalt = globalSalt;
    }

    /**
     * Generates a blind index for the given plaintext and per-record salt.
     *
     * <p>The blind index is computed as:
     * HMAC-SHA256(blind_index_key, global_salt || record_salt || normalized_plaintext)
     *
     * <p>Normalization: lowercase + trim.
     *
     * @param plaintext  the plaintext value to generate a blind index for
     * @param recordSalt the unique per-record salt (resists pattern matching)
     * @return Result containing the hex-encoded BlindIndex, or EncryptionError on failure
     */
    public Result<BlindIndex, EncryptionError> generateBlindIndex(String plaintext, String recordSalt) {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        Objects.requireNonNull(recordSalt, "Record salt cannot be null");

        // 1. Retrieve the blind index key from KeyManager
        Result<byte[], KeyError> keyResult = keyManager.getBlindIndexKey();
        if (keyResult.isFailure()) {
            KeyError keyError = keyResult.getError().orElseThrow();
            return Result.failure(EncryptionError.of(
                "BLIND_INDEX_KEY_UNAVAILABLE",
                "Failed to retrieve blind index key: " + keyError.getMessage(),
                keyError.getCause()
            ));
        }

        byte[] blindIndexKey = keyResult.getValue().orElseThrow();

        try {
            // 2. Normalize plaintext: lowercase + trim 
            String normalized = plaintext.trim().toLowerCase();

            // 3. Build HMAC message: global_salt || record_salt || normalized_plaintext
            String message = globalSalt + recordSalt + normalized;
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

            // 4. Compute HMAC-SHA256 
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(blindIndexKey, HMAC_ALGORITHM));
            byte[] hmacBytes = mac.doFinal(messageBytes);

            // 5. Hex-encode the result
            String hexValue = HexFormat.of().formatHex(hmacBytes);

            return Result.success(BlindIndex.of(hexValue));

        } catch (Exception e) {
            return Result.failure(EncryptionError.of(
                "BLIND_INDEX_GENERATION_FAILED",
                "Failed to generate blind index: " + e.getMessage(),
                e
            ));
        }
    }

    /**
     * Verifies a blind index against a plaintext and per-record salt in constant time.
     *
     * <p>Uses {@link ConstantTime#verifyHmac} to prevent timing side-channel attacks.
     *
     * @param plaintext  the plaintext to verify
     * @param recordSalt the per-record salt used when the blind index was generated
     * @param expected   the expected blind index
     * @return {@code true} if the blind index matches, {@code false} otherwise
     */
    public boolean verifyBlindIndex(String plaintext, String recordSalt, BlindIndex expected) {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        Objects.requireNonNull(recordSalt, "Record salt cannot be null");
        Objects.requireNonNull(expected, "Expected blind index cannot be null");

        Result<BlindIndex, EncryptionError> result = generateBlindIndex(plaintext, recordSalt);
        if (result.isFailure()) {
            return false;
        }

        BlindIndex actual = result.getValue().orElseThrow();
        // Constant-time comparison to prevent timing attacks 
        byte[] expectedBytes = expected.getValue().getBytes(StandardCharsets.UTF_8);
        byte[] actualBytes = actual.getValue().getBytes(StandardCharsets.UTF_8);
        return ConstantTime.verifyHmac(expectedBytes, actualBytes);
    }
}
