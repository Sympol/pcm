package dev.vibeafrika.pcm.domain.encryption.config;

import java.util.Objects;

/**
 * Policy governing automatic DEK and KEK rotation schedules.
 *
 * <p>DEK rotation is triggered by whichever threshold is reached first:
 * <ul>
 *   <li>Age: {@link #dekRotationDays} days since DEK creation (default 90).</li>
 *   <li>Volume: {@link #dekRotationBytes} bytes encrypted (default 1 TB).</li>
 *   <li>Operations: {@link #dekRotationOperations} encryption operations (default 2^32).</li>
 * </ul>
 *
 * <p>KEK rotation is governed by {@link #kekRotationDays} (default 365).
 * Emergency rotation must complete within {@link #emergencyRotationTimeMinutes} minutes
 * (default 15).
 */
public final class KeyRotationPolicy {

    /** Default DEK rotation age in days. */
    public static final int DEFAULT_DEK_ROTATION_DAYS = 90;

    /** Default DEK rotation volume threshold in bytes (1 TB). */
    public static final long DEFAULT_DEK_ROTATION_BYTES = 1_099_511_627_776L;

    /** Default DEK rotation operation count threshold (2^32). */
    public static final long DEFAULT_DEK_ROTATION_OPERATIONS = 4_294_967_296L;

    /** Default KEK rotation age in days. */
    public static final int DEFAULT_KEK_ROTATION_DAYS = 365;

    /** Default emergency rotation time limit in minutes. */
    public static final int DEFAULT_EMERGENCY_ROTATION_TIME_MINUTES = 15;

    private final int dekRotationDays;
    private final long dekRotationBytes;
    private final long dekRotationOperations;
    private final int kekRotationDays;
    private final int emergencyRotationTimeMinutes;

    private KeyRotationPolicy(Builder builder) {
        this.dekRotationDays = builder.dekRotationDays;
        this.dekRotationBytes = builder.dekRotationBytes;
        this.dekRotationOperations = builder.dekRotationOperations;
        this.kekRotationDays = builder.kekRotationDays;
        this.emergencyRotationTimeMinutes = builder.emergencyRotationTimeMinutes;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Creates a policy with all default values. */
    public static KeyRotationPolicy defaults() {
        return new Builder().build();
    }

    public int getDekRotationDays() {
        return dekRotationDays;
    }

    public long getDekRotationBytes() {
        return dekRotationBytes;
    }

    public long getDekRotationOperations() {
        return dekRotationOperations;
    }

    public int getKekRotationDays() {
        return kekRotationDays;
    }

    public int getEmergencyRotationTimeMinutes() {
        return emergencyRotationTimeMinutes;
    }

    public static final class Builder {
        private int dekRotationDays = DEFAULT_DEK_ROTATION_DAYS;
        private long dekRotationBytes = DEFAULT_DEK_ROTATION_BYTES;
        private long dekRotationOperations = DEFAULT_DEK_ROTATION_OPERATIONS;
        private int kekRotationDays = DEFAULT_KEK_ROTATION_DAYS;
        private int emergencyRotationTimeMinutes = DEFAULT_EMERGENCY_ROTATION_TIME_MINUTES;

        private Builder() {}

        public Builder dekRotationDays(int dekRotationDays) {
            this.dekRotationDays = dekRotationDays;
            return this;
        }

        public Builder dekRotationBytes(long dekRotationBytes) {
            this.dekRotationBytes = dekRotationBytes;
            return this;
        }

        public Builder dekRotationOperations(long dekRotationOperations) {
            this.dekRotationOperations = dekRotationOperations;
            return this;
        }

        public Builder kekRotationDays(int kekRotationDays) {
            this.kekRotationDays = kekRotationDays;
            return this;
        }

        public Builder emergencyRotationTimeMinutes(int emergencyRotationTimeMinutes) {
            this.emergencyRotationTimeMinutes = emergencyRotationTimeMinutes;
            return this;
        }

        public KeyRotationPolicy build() {
            return new KeyRotationPolicy(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyRotationPolicy that = (KeyRotationPolicy) o;
        return dekRotationDays == that.dekRotationDays &&
                dekRotationBytes == that.dekRotationBytes &&
                dekRotationOperations == that.dekRotationOperations &&
                kekRotationDays == that.kekRotationDays &&
                emergencyRotationTimeMinutes == that.emergencyRotationTimeMinutes;
    }

    @Override
    public int hashCode() {
        return Objects.hash(dekRotationDays, dekRotationBytes, dekRotationOperations,
                kekRotationDays, emergencyRotationTimeMinutes);
    }

    @Override
    public String toString() {
        return "KeyRotationPolicy{" +
                "dekRotationDays=" + dekRotationDays +
                ", dekRotationBytes=" + dekRotationBytes +
                ", dekRotationOperations=" + dekRotationOperations +
                ", kekRotationDays=" + kekRotationDays +
                ", emergencyRotationTimeMinutes=" + emergencyRotationTimeMinutes +
                '}';
    }
}
