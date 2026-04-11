package dev.vibeafrika.pcm.infrastructure.encryption;

import dev.vibeafrika.pcm.domain.encryption.Ciphertext;
import dev.vibeafrika.pcm.domain.encryption.EncryptionAlgorithm;
import dev.vibeafrika.pcm.domain.encryption.Result;
import dev.vibeafrika.pcm.domain.encryption.DecryptionError;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;
import java.util.UUID;

/**
 * Handles serialization and deserialization of the ciphertext binary format.
 * 
 * <p>Ciphertext Format:
 * <pre>
 * +--------+--------+------------------+------------+-------------+--------+
 * | Version| Alg ID |     Key ID       |     IV     |  Ciphertext |  Tag   |
 * | 1 byte | 1 byte |    16 bytes      |  12 bytes  |   N bytes   |16 bytes|
 * +--------+--------+------------------+------------+-------------+--------+
 * </pre>
 * 
 * <p>Field Specifications:
 * <ul>
 *   <li><b>Version</b> (1 byte): Ciphertext format version (0x01 for initial version)</li>
 *   <li><b>Algorithm ID</b> (1 byte): Encryption algorithm identifier
 *       <ul>
 *         <li>0x01: AES-256-GCM</li>
 *         <li>0x02: AES-256-CBC with HMAC-SHA256</li>
 *       </ul>
 *   </li>
 *   <li><b>Key ID</b> (16 bytes): UUID of the DEK used for encryption, stored in big-endian format</li>
 *   <li><b>IV</b> (12 bytes): Initialization Vector (96-bit for AES-256-GCM)</li>
 *   <li><b>Ciphertext</b> (N bytes): Encrypted data (variable length)</li>
 *   <li><b>Authentication Tag</b> (16 bytes): GCM authentication tag</li>
 * </ul>
 * 
 * <p>Total Overhead: 46 bytes + ciphertext length
 * 
 */
public final class CiphertextFormat {

    // Format version constants
    public static final byte VERSION_1 = 0x01;

    // Algorithm ID constants
    public static final byte ALGORITHM_AES_256_GCM = 0x01;
    public static final byte ALGORITHM_AES_256_CBC_HMAC = 0x02;

    // Field sizes
    private static final int VERSION_SIZE = 1;
    private static final int ALGORITHM_ID_SIZE = 1;
    private static final int KEY_ID_SIZE = 16;
    private static final int IV_SIZE = 12;
    private static final int AUTH_TAG_SIZE = 16;
    private static final int HEADER_SIZE = VERSION_SIZE + ALGORITHM_ID_SIZE + KEY_ID_SIZE + IV_SIZE;
    private static final int MINIMUM_CIPHERTEXT_SIZE = HEADER_SIZE + AUTH_TAG_SIZE; // 46 bytes

    // Field offsets
    private static final int VERSION_OFFSET = 0;
    private static final int ALGORITHM_ID_OFFSET = 1;
    private static final int KEY_ID_OFFSET = 2;
    private static final int IV_OFFSET = 18;
    private static final int CIPHERTEXT_OFFSET = 30;

    private CiphertextFormat() {
        // Utility class - prevent instantiation
    }

    /**
     * Formats encryption components into the standard ciphertext binary format.
     * 
     * @param version the format version byte (should be VERSION_1)
     * @param algorithmId the algorithm identifier byte
     * @param keyId the UUID of the DEK used for encryption
     * @param iv the initialization vector (12 bytes for AES-256-GCM)
     * @param ciphertext the encrypted data
     * @param authTag the authentication tag (16 bytes for GCM)
     * @return Result containing the formatted Ciphertext or an error
     */
    public static Result<Ciphertext, DecryptionError> format(
            byte version,
            byte algorithmId,
            UUID keyId,
            byte[] iv,
            byte[] ciphertext,
            byte[] authTag) {

        // Validate inputs
        if (keyId == null) {
            return Result.failure(DecryptionError.of("INVALID_FORMAT", "Key ID cannot be null"));
        }
        if (iv == null || iv.length != IV_SIZE) {
            return Result.failure(DecryptionError.of("INVALID_FORMAT", 
                "IV must be exactly " + IV_SIZE + " bytes"));
        }
        if (ciphertext == null) {
            return Result.failure(DecryptionError.of("INVALID_FORMAT", "Ciphertext cannot be null"));
        }
        if (authTag == null || authTag.length != AUTH_TAG_SIZE) {
            return Result.failure(DecryptionError.of("INVALID_FORMAT", 
                "Authentication tag must be exactly " + AUTH_TAG_SIZE + " bytes"));
        }

        try {
            // Calculate total size
            int totalSize = HEADER_SIZE + ciphertext.length + AUTH_TAG_SIZE;
            ByteBuffer buffer = ByteBuffer.allocate(totalSize);
            buffer.order(ByteOrder.BIG_ENDIAN);

            // Write version
            buffer.put(version);

            // Write algorithm ID
            buffer.put(algorithmId);

            // Write key ID (UUID in big-endian format)
            buffer.putLong(keyId.getMostSignificantBits());
            buffer.putLong(keyId.getLeastSignificantBits());

            // Write IV
            buffer.put(iv);

            // Write ciphertext
            buffer.put(ciphertext);

            // Write authentication tag
            buffer.put(authTag);

            return Result.success(Ciphertext.of(buffer.array()));

        } catch (Exception e) {
            // Do not include e.getMessage() – it may contain sensitive data (req 8.6)
            return Result.failure(DecryptionError.of("FORMAT_ERROR",
                "Failed to format ciphertext"));
        }
    }

    /**
     * Parses a ciphertext byte array into its component parts.
     * 
     * @param ciphertext the ciphertext to parse
     * @return Result containing the parsed components or an error
     */
    public static Result<ParsedCiphertext, DecryptionError> parse(Ciphertext ciphertext) {
        Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
        return parse(ciphertext.getValue());
    }

    /**
     * Parses a ciphertext byte array into its component parts.
     * 
     * @param bytes the ciphertext bytes to parse
     * @return Result containing the parsed components or an error
     */
    public static Result<ParsedCiphertext, DecryptionError> parse(byte[] bytes) {
        if (bytes == null) {
            return Result.failure(DecryptionError.of("INVALID_CIPHERTEXT_FORMAT", 
                "Ciphertext bytes cannot be null"));
        }

        if (bytes.length < MINIMUM_CIPHERTEXT_SIZE) {
            return Result.failure(DecryptionError.of("INVALID_CIPHERTEXT_FORMAT", 
                "Ciphertext too short: expected at least " + MINIMUM_CIPHERTEXT_SIZE + 
                " bytes, got " + bytes.length));
        }

        try {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            buffer.order(ByteOrder.BIG_ENDIAN);

            // Parse version
            byte version = buffer.get(VERSION_OFFSET);
            if (version != VERSION_1) {
                return Result.failure(DecryptionError.of("UNSUPPORTED_VERSION", 
                    "Unsupported ciphertext version: 0x" + String.format("%02X", version)));
            }

            // Parse algorithm ID
            byte algorithmId = buffer.get(ALGORITHM_ID_OFFSET);
            EncryptionAlgorithm algorithm = algorithmIdToEnum(algorithmId);
            if (algorithm == null) {
                return Result.failure(DecryptionError.of("UNSUPPORTED_ALGORITHM", 
                    "Unsupported algorithm ID: 0x" + String.format("%02X", algorithmId)));
            }

            // Parse key ID (UUID in big-endian format)
            buffer.position(KEY_ID_OFFSET);
            long mostSigBits = buffer.getLong();
            long leastSigBits = buffer.getLong();
            UUID keyId = new UUID(mostSigBits, leastSigBits);

            // Parse IV
            byte[] iv = new byte[IV_SIZE];
            buffer.position(IV_OFFSET);
            buffer.get(iv);

            // Parse ciphertext (everything between IV and auth tag)
            int ciphertextLength = bytes.length - HEADER_SIZE - AUTH_TAG_SIZE;
            byte[] ciphertextBytes = new byte[ciphertextLength];
            buffer.position(CIPHERTEXT_OFFSET);
            buffer.get(ciphertextBytes);

            // Parse authentication tag (last 16 bytes)
            byte[] authTag = new byte[AUTH_TAG_SIZE];
            buffer.position(bytes.length - AUTH_TAG_SIZE);
            buffer.get(authTag);

            return Result.success(new ParsedCiphertext(
                version,
                algorithm,
                keyId,
                iv,
                ciphertextBytes,
                authTag
            ));

        } catch (Exception e) {
            // Do not include e.getMessage() – it may contain sensitive data (req 8.6)
            return Result.failure(DecryptionError.of("PARSE_ERROR",
                "Failed to parse ciphertext"));
        }
    }

    /**
     * Converts an EncryptionAlgorithm enum to its byte identifier.
     * 
     * @param algorithm the encryption algorithm
     * @return the algorithm ID byte
     */
    public static byte algorithmToId(EncryptionAlgorithm algorithm) {
        Objects.requireNonNull(algorithm, "Algorithm cannot be null");
        switch (algorithm) {
            case AES_256_GCM:
                return ALGORITHM_AES_256_GCM;
            case AES_256_CBC_HMAC:
                return ALGORITHM_AES_256_CBC_HMAC;
            default:
                throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
        }
    }

    /**
     * Converts an algorithm ID byte to its EncryptionAlgorithm enum.
     * 
     * @param algorithmId the algorithm ID byte
     * @return the EncryptionAlgorithm enum, or null if unsupported
     */
    private static EncryptionAlgorithm algorithmIdToEnum(byte algorithmId) {
        switch (algorithmId) {
            case ALGORITHM_AES_256_GCM:
                return EncryptionAlgorithm.AES_256_GCM;
            case ALGORITHM_AES_256_CBC_HMAC:
                return EncryptionAlgorithm.AES_256_CBC_HMAC;
            default:
                return null;
        }
    }

    /**
     * Value object containing the parsed components of a ciphertext.
     */
    public static final class ParsedCiphertext {
        private final byte version;
        private final EncryptionAlgorithm algorithm;
        private final UUID keyId;
        private final byte[] iv;
        private final byte[] ciphertext;
        private final byte[] authTag;

        public ParsedCiphertext(
                byte version,
                EncryptionAlgorithm algorithm,
                UUID keyId,
                byte[] iv,
                byte[] ciphertext,
                byte[] authTag) {
            this.version = version;
            this.algorithm = Objects.requireNonNull(algorithm, "Algorithm cannot be null");
            this.keyId = Objects.requireNonNull(keyId, "Key ID cannot be null");
            this.iv = Objects.requireNonNull(iv, "IV cannot be null");
            this.ciphertext = Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
            this.authTag = Objects.requireNonNull(authTag, "Auth tag cannot be null");
        }

        public byte getVersion() {
            return version;
        }

        public EncryptionAlgorithm getAlgorithm() {
            return algorithm;
        }

        public UUID getKeyId() {
            return keyId;
        }

        public byte[] getIv() {
            return iv.clone();
        }

        public byte[] getCiphertext() {
            return ciphertext.clone();
        }

        public byte[] getAuthTag() {
            return authTag.clone();
        }

        @Override
        public String toString() {
            return "ParsedCiphertext{" +
                    "version=0x" + String.format("%02X", version) +
                    ", algorithm=" + algorithm +
                    ", keyId=" + keyId +
                    ", ivLength=" + iv.length +
                    ", ciphertextLength=" + ciphertext.length +
                    ", authTagLength=" + authTag.length +
                    '}';
        }
    }
}
