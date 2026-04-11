package dev.vibeafrika.pcm.domain.encryption;

/**
 * Centralized error codes for all encryption-related operations.
 *
 * <p>Codes are grouped by domain:
 * <ul>
 *   <li>Encryption errors – failures during encrypt/IV generation</li>
 *   <li>Decryption errors – failures during decrypt/format parsing</li>
 *   <li>Key management errors – DEK/KEK lifecycle failures</li>
 *   <li>KMS errors – remote key management system failures</li>
 *   <li>Audit errors – audit logging failures</li>
 *   <li>Configuration errors – configuration parsing/validation failures</li>
 *   <li>Environment errors – environment isolation and entropy failures</li>
 * </ul>
 */
public enum EncryptionErrorCodes {

    // -------------------------------------------------------------------------
    // Encryption errors
    // -------------------------------------------------------------------------

    /** Generic encryption failure. */
    ENCRYPTION_FAILED("Encryption operation failed"),

    /** The plaintext value is null, empty, or otherwise invalid. */
    INVALID_PLAINTEXT("Plaintext is null or invalid"),

    /** The counter-based IV generator could not produce a new IV. */
    IV_GENERATION_FAILED("IV generation failed"),

    /**
     * The IV counter has reached 2^32 operations for the current DEK.
     * DEK rotation must complete before further encryption is allowed.
     */
    COUNTER_OVERFLOW("IV counter overflow – DEK rotation required"),

    // -------------------------------------------------------------------------
    // Decryption errors
    // -------------------------------------------------------------------------

    /** Generic decryption failure. */
    DECRYPTION_FAILED("Decryption operation failed"),

    /** The ciphertext does not conform to the expected binary format. */
    INVALID_CIPHERTEXT_FORMAT("Ciphertext format is invalid"),

    /** The ciphertext version byte is not supported by this implementation. */
    UNSUPPORTED_VERSION("Ciphertext version is not supported"),

    /** The algorithm identifier in the ciphertext is not supported. */
    UNSUPPORTED_ALGORITHM("Encryption algorithm is not supported"),

    /** The GCM authentication tag verification failed – data may have been tampered with. */
    TAMPERING_DETECTED("Ciphertext authentication tag verification failed – tampering detected"),

    // -------------------------------------------------------------------------
    // Key management errors
    // -------------------------------------------------------------------------

    /** The requested DEK or KEK could not be found. */
    KEY_NOT_FOUND("Encryption key not found"),

    /** The key exists but is currently unavailable (e.g. KMS unreachable). */
    KEY_UNAVAILABLE("Encryption key is unavailable"),

    /** The DEK or KEK rotation operation failed. */
    KEY_ROTATION_FAILED("Key rotation failed"),

    /** The key material is malformed or does not meet length requirements. */
    INVALID_KEY_FORMAT("Key format is invalid"),

    /** The key has passed its maximum allowed age or operation count. */
    KEY_EXPIRED("Encryption key has expired"),

    // -------------------------------------------------------------------------
    // KMS errors
    // -------------------------------------------------------------------------

    /** The KMS is unreachable or returned a service-unavailable response. */
    KMS_UNAVAILABLE("KMS is unavailable"),

    /** The service identity could not be authenticated by the KMS. */
    KMS_AUTHENTICATION_FAILED("KMS authentication failed"),

    /** The service identity is not authorized to perform the requested KMS operation. */
    KMS_AUTHORIZATION_FAILED("KMS authorization failed"),

    /** The KMS request exceeded the configured timeout. */
    KMS_TIMEOUT("KMS request timed out"),

    // -------------------------------------------------------------------------
    // Audit errors
    // -------------------------------------------------------------------------

    /** An audit log entry could not be written. */
    AUDIT_LOG_FAILED("Audit log write failed"),

    /** An audit log entry failed HMAC signature verification. */
    AUDIT_LOG_INTEGRITY_VIOLATION("Audit log integrity violation detected"),

    // -------------------------------------------------------------------------
    // Configuration errors
    // -------------------------------------------------------------------------

    /** Generic configuration validation failure. */
    INVALID_CONFIGURATION("Configuration is invalid"),

    /** The specified encryption algorithm is not recognized or not permitted. */
    INVALID_ALGORITHM("Encryption algorithm specification is invalid"),

    /** One or more KMS connection parameters are missing or malformed. */
    INVALID_KMS_PARAMETERS("KMS connection parameters are invalid"),

    // -------------------------------------------------------------------------
    // Environment errors
    // -------------------------------------------------------------------------

    /**
     * A key loaded from the KMS carries an environment identifier that does not
     * match the current runtime environment.
     */
    ENVIRONMENT_MISMATCH("Key environment does not match current environment"),

    /**
     * The operating-system entropy source (e.g. /dev/urandom, SecureRandom) is
     * unavailable or failed validation at startup.
     */
    ENTROPY_SOURCE_UNAVAILABLE("Cryptographic entropy source is unavailable");

    // -------------------------------------------------------------------------

    private final String defaultMessage;

    EncryptionErrorCodes(String defaultMessage) {
        this.defaultMessage = defaultMessage;
    }

    /** Returns the human-readable default message for this error code. */
    public String getDefaultMessage() {
        return defaultMessage;
    }

    /** Returns the enum name, which is the canonical string code used in error objects. */
    public String code() {
        return name();
    }
}
