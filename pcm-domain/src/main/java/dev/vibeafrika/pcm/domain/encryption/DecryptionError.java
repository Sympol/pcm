package dev.vibeafrika.pcm.domain.encryption;

import java.util.Objects;

/**
 * Represents an error that occurred during decryption operations.
 */
public final class DecryptionError {
    private final String code;
    private final String message;
    private final Throwable cause;

    private DecryptionError(String code, String message, Throwable cause) {
        this.code = code;
        this.message = message;
        this.cause = cause;
    }

    public static DecryptionError of(String code, String message) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new DecryptionError(code, message, null);
    }

    public static DecryptionError of(String code, String message, Throwable cause) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new DecryptionError(code, message, cause);
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
        DecryptionError that = (DecryptionError) o;
        return Objects.equals(code, that.code) &&
                Objects.equals(message, that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, message);
    }

    @Override
    public String toString() {
        return "DecryptionError{code=" + code + ", message=" + message + "}";
    }
}
