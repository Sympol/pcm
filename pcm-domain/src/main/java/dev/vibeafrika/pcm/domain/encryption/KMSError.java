package dev.vibeafrika.pcm.domain.encryption;

import java.util.Objects;

/**
 * Represents an error that occurred during KMS operations.
 */
public final class KMSError {
    private final String code;
    private final String message;
    private final Throwable cause;

    private KMSError(String code, String message, Throwable cause) {
        this.code = code;
        this.message = message;
        this.cause = cause;
    }

    public static KMSError of(String code, String message) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new KMSError(code, message, null);
    }

    public static KMSError of(String code, String message, Throwable cause) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new KMSError(code, message, cause);
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
        KMSError that = (KMSError) o;
        return Objects.equals(code, that.code) &&
                Objects.equals(message, that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, message);
    }

    @Override
    public String toString() {
        return "KMSError{code=" + code + ", message=" + message + "}";
    }
}
