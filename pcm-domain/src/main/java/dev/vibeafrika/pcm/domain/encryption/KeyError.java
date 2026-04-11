package dev.vibeafrika.pcm.domain.encryption;

import java.util.Objects;

/**
 * Represents an error that occurred during key management operations.
 */
public final class KeyError {
    private final String code;
    private final String message;
    private final Throwable cause;

    private KeyError(String code, String message, Throwable cause) {
        this.code = code;
        this.message = message;
        this.cause = cause;
    }

    public static KeyError of(String code, String message) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new KeyError(code, message, null);
    }

    public static KeyError of(String code, String message, Throwable cause) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new KeyError(code, message, cause);
    }

    /** Creates a {@code KeyError} using a typed {@link EncryptionErrorCodes} constant. */
    public static KeyError of(EncryptionErrorCodes code, String message) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new KeyError(code.code(), message, null);
    }

    /** Creates a {@code KeyError} using a typed {@link EncryptionErrorCodes} constant with a cause. */
    public static KeyError of(EncryptionErrorCodes code, String message, Throwable cause) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new KeyError(code.code(), message, cause);
    }

    /** Creates a {@code KeyError} using the default message from the error code. */
    public static KeyError of(EncryptionErrorCodes code) {
        Objects.requireNonNull(code, "Error code cannot be null");
        return new KeyError(code.code(), code.getDefaultMessage(), null);
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
        KeyError that = (KeyError) o;
        return Objects.equals(code, that.code) &&
                Objects.equals(message, that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, message);
    }

    @Override
    public String toString() {
        return "KeyError{code=" + code + ", message=" + message + "}";
    }
}
