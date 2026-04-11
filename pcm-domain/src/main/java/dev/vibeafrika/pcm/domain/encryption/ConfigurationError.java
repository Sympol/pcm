package dev.vibeafrika.pcm.domain.encryption;

import java.util.Objects;

/**
 * Represents an error that occurred during configuration parsing or validation.
 *
 * <p>Common error codes:
 * <ul>
 *   <li>{@code EMPTY_INPUT} – the configuration content was null or blank.</li>
 *   <li>{@code YAML_PARSE_ERROR} – the YAML content could not be parsed.</li>
 *   <li>{@code JSON_PARSE_ERROR} – the JSON content could not be parsed.</li>
 *   <li>{@code IO_ERROR} – an I/O error occurred while reading the configuration.</li>
 *   <li>{@code MISSING_REQUIRED_SECTIONS} – one or more required sections are absent.</li>
 *   <li>{@code INVALID_ALGORITHM} – the encryption algorithm specification is invalid.</li>
 *   <li>{@code INVALID_KMS_PARAMETERS} – one or more KMS connection parameters are invalid.</li>
 *   <li>{@code INVALID_CONFIGURATION} – generic configuration validation failure.</li>
 * </ul>
 */
public final class ConfigurationError {

    private final String code;
    private final String message;
    private final Throwable cause;

    private ConfigurationError(String code, String message, Throwable cause) {
        this.code = code;
        this.message = message;
        this.cause = cause;
    }

    public static ConfigurationError of(String code, String message) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new ConfigurationError(code, message, null);
    }

    public static ConfigurationError of(String code, String message, Throwable cause) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new ConfigurationError(code, message, cause);
    }

    /** Creates a {@code ConfigurationError} using a typed {@link EncryptionErrorCodes} constant. */
    public static ConfigurationError of(EncryptionErrorCodes code, String message) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new ConfigurationError(code.code(), message, null);
    }

    /** Creates a {@code ConfigurationError} using a typed {@link EncryptionErrorCodes} constant with a cause. */
    public static ConfigurationError of(EncryptionErrorCodes code, String message, Throwable cause) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new ConfigurationError(code.code(), message, cause);
    }

    /** Creates a {@code ConfigurationError} using the default message from the error code. */
    public static ConfigurationError of(EncryptionErrorCodes code) {
        Objects.requireNonNull(code, "Error code cannot be null");
        return new ConfigurationError(code.code(), code.getDefaultMessage(), null);
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public Throwable getCause() {
        return cause;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ConfigurationError that = (ConfigurationError) o;
        return Objects.equals(code, that.code) &&
                Objects.equals(message, that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, message);
    }

    @Override
    public String toString() {
        return "ConfigurationError{code=" + code + ", message=" + message + "}";
    }
}
