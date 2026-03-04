package dev.vibeafrika.pcm.domain.encryption;

/**
 * Error type for IV counter operations.
 */
public final class IVCounterError {
    private final String code;
    private final String message;

    private IVCounterError(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public static IVCounterError counterOverflow(String dekId) {
        return new IVCounterError("IV_COUNTER_OVERFLOW", 
            "Counter overflow detected for DEK " + dekId + ". DEK rotation required.");
    }

    public static IVCounterError persistenceFailed(String dekId, String reason) {
        return new IVCounterError("IV_COUNTER_PERSISTENCE_FAILED", 
            "Failed to persist counter state for DEK " + dekId + ": " + reason);
    }

    public static IVCounterError loadFailed(String dekId, String reason) {
        return new IVCounterError("IV_COUNTER_LOAD_FAILED", 
            "Failed to load counter state for DEK " + dekId + ": " + reason);
    }

    public static IVCounterError invalidState(String reason) {
        return new IVCounterError("IV_COUNTER_INVALID_STATE", 
            "Invalid counter state: " + reason);
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return "IVCounterError{code='" + code + "', message='" + message + "'}";
    }
}
