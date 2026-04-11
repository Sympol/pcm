package dev.vibeafrika.pcm.domain.encryption.config;

import java.util.Objects;
import java.util.Optional;

/**
 * Configuration model for the audit logging subsystem as part of
 * {@link EncryptionConfiguration}.
 *
 * <p>This model captures the full set of audit settings, including log retention, at-rest encryption,
 * integrity signing, and optional sampling for high-volume operations.
 *
 * <p>Note: this class is named {@code AuditConfigurationModel} to avoid a
 * name clash with the existing
 * {@link dev.vibeafrika.pcm.domain.encryption.AuditConfiguration} class in
 * the parent package, which focuses on runtime log-level filtering.
 */
public final class AuditConfigurationModel {

    /** Default log retention period in days (1 year). */
    public static final int DEFAULT_RETENTION_DAYS = 365;

    private final AuditLevel level;
    private final int retentionDays;
    private final boolean encryptLogs;
    private final boolean signLogs;
    private final Double samplingRate;

    private AuditConfigurationModel(Builder builder) {
        this.level = Objects.requireNonNull(builder.level, "level cannot be null");
        if (builder.retentionDays < 1) {
            throw new IllegalArgumentException("retentionDays must be >= 1");
        }
        this.retentionDays = builder.retentionDays;
        this.encryptLogs = builder.encryptLogs;
        this.signLogs = builder.signLogs;
        if (builder.samplingRate != null &&
                (builder.samplingRate <= 0.0 || builder.samplingRate > 1.0)) {
            throw new IllegalArgumentException("samplingRate must be in (0, 1] when present");
        }
        this.samplingRate = builder.samplingRate;
    }

    public static Builder builder() {
        return new Builder();
    }

    public AuditLevel getLevel() {
        return level;
    }

    /** Number of days audit logs are retained. */
    public int getRetentionDays() {
        return retentionDays;
    }

    /** Whether audit logs are encrypted at rest. */
    public boolean isEncryptLogs() {
        return encryptLogs;
    }

    /** Whether audit log entries are signed for integrity verification. */
    public boolean isSignLogs() {
        return signLogs;
    }

    /**
     * Optional sampling rate in the range {@code (0, 1]}.
     * When present, only this fraction of high-volume operations are logged.
     * A value of {@code 1.0} means log every event.
     */
    public Optional<Double> getSamplingRate() {
        return Optional.ofNullable(samplingRate);
    }

    public static final class Builder {
        private AuditLevel level = AuditLevel.HIGH;
        private int retentionDays = DEFAULT_RETENTION_DAYS;
        private boolean encryptLogs = true;
        private boolean signLogs = true;
        private Double samplingRate;

        private Builder() {}

        public Builder level(AuditLevel level) {
            this.level = level;
            return this;
        }

        public Builder retentionDays(int retentionDays) {
            this.retentionDays = retentionDays;
            return this;
        }

        public Builder encryptLogs(boolean encryptLogs) {
            this.encryptLogs = encryptLogs;
            return this;
        }

        public Builder signLogs(boolean signLogs) {
            this.signLogs = signLogs;
            return this;
        }

        public Builder samplingRate(Double samplingRate) {
            this.samplingRate = samplingRate;
            return this;
        }

        public AuditConfigurationModel build() {
            return new AuditConfigurationModel(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditConfigurationModel that = (AuditConfigurationModel) o;
        return retentionDays == that.retentionDays &&
                encryptLogs == that.encryptLogs &&
                signLogs == that.signLogs &&
                level == that.level &&
                Objects.equals(samplingRate, that.samplingRate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(level, retentionDays, encryptLogs, signLogs, samplingRate);
    }

    @Override
    public String toString() {
        return "AuditConfigurationModel{" +
                "level=" + level +
                ", retentionDays=" + retentionDays +
                ", encryptLogs=" + encryptLogs +
                ", signLogs=" + signLogs +
                ", samplingRate=" + samplingRate +
                '}';
    }
}
