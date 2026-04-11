package dev.vibeafrika.pcm.domain.encryption;

import java.util.Objects;

/**
 * Represents an error that occurred during backup operations.
 */
public final class BackupError {
    private final String code;
    private final String message;
    private final Throwable cause;

    private BackupError(String code, String message, Throwable cause) {
        this.code = code;
        this.message = message;
        this.cause = cause;
    }

    public static BackupError of(String code, String message) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new BackupError(code, message, null);
    }

    public static BackupError of(String code, String message, Throwable cause) {
        Objects.requireNonNull(code, "Error code cannot be null");
        Objects.requireNonNull(message, "Error message cannot be null");
        return new BackupError(code, message, cause);
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
        BackupError that = (BackupError) o;
        return Objects.equals(code, that.code) && Objects.equals(message, that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, message);
    }

    @Override
    public String toString() {
        return "BackupError{code=" + code + ", message=" + message + "}";
    }
}
