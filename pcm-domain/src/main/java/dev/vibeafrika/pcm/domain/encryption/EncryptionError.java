package dev.vibeafrika.pcm.domain.encryption;

import java.util.Objects;

/**
 * Represents an error that occurred during encryption operations.
 */
public final class EncryptionError {
    private final String code;
    private final String message;
    private final Throwable cause;

    private EncryptionError(String code, String message, Throwable cause) {
        this.code = code;
        this.message = message;
        this.cause = cause;
    }

    public static EncryptionError of(String code, String message) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new EncryptionError(code, message, null);
    }

    public static EncryptionError of(String code, String message, Throwable cause) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new EncryptionError(code, message, cause);
    }

    /** Creates an {@code EncryptionError} using a typed {@link EncryptionErrorCodes} constant. */
    public static EncryptionError of(EncryptionErrorCodes code, String message) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new EncryptionError(code.code(), message, null);
    }

    /** Creates an {@code EncryptionError} using a typed {@link EncryptionErrorCodes} constant with a cause. */
    public static EncryptionError of(EncryptionErrorCodes code, String message, Throwable cause) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new EncryptionError(code.code(), message, cause);
    }

    /** Creates an {@code EncryptionError} using the default message from the error code. */
    public static EncryptionError of(EncryptionErrorCodes code) {
        Objects.requireNonNull(code, "Error code cannot be null");
        return new EncryptionError(code.code(), code.getDefaultMessage(), null);
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
        EncryptionError that = (EncryptionError) o;
        return Objects.equals(code, that.code) &&
                Objects.equals(message, that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, message);
    }

    @Override
    public String toString() {
        return "EncryptionError{code=" + code + ", message=" + message + "}";
    }
}
