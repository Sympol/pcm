package dev.vibeafrika.pcm.domain.encryption;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * Configuration model for the audit logging subsystem.
 *
 * <p>Controls:
 * <ul>
 *   <li>Minimum log level – events below this level are filtered out, except
 *       {@link LogLevel#CRITICAL} which is always logged (Requirement 21.4).</li>
 *   <li>Sampling rate – for levels subject to sampling, log 1 in every N events
 *       to reduce storage pressure on high-volume operations (Requirement 21.3).</li>
 *   <li>Sampled levels – which levels are subject to sampling (default: LOW).</li>
 * </ul>
 */
public final class AuditConfiguration {

    /** Default minimum level: log everything. */
    public static final LogLevel DEFAULT_MINIMUM_LEVEL = LogLevel.LOW;

    /** Default sampling rate: log every event (no sampling). */
    public static final int DEFAULT_SAMPLING_RATE = 1;

    /** Default sampled levels: only LOW-level events are sampled by default. */
    public static final Set<LogLevel> DEFAULT_SAMPLED_LEVELS =
            Collections.unmodifiableSet(EnumSet.of(LogLevel.LOW));

    private final LogLevel minimumLevel;
    private final int samplingRate;
    private final Set<LogLevel> sampledLevels;

    private AuditConfiguration(Builder builder) {
        this.minimumLevel = Objects.requireNonNull(builder.minimumLevel, "minimumLevel cannot be null");
        if (builder.samplingRate < 1) {
            throw new IllegalArgumentException("samplingRate must be >= 1 (1 = log all)");
        }
        this.samplingRate = builder.samplingRate;
        this.sampledLevels = builder.sampledLevels != null
                ? Collections.unmodifiableSet(EnumSet.copyOf(builder.sampledLevels))
                : DEFAULT_SAMPLED_LEVELS;
    }

    /**
     * Creates a default configuration: minimum level LOW, sampling rate 1 (log all),
     * sampled levels = {LOW}.
     */
    public static AuditConfiguration defaults() {
        return new Builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * The minimum log level. Events below this level are filtered out.
     * CRITICAL events are always logged regardless of this setting.
     */
    public LogLevel getMinimumLevel() {
        return minimumLevel;
    }

    /**
     * Sampling rate N: log 1 in every N events for levels in {@link #getSampledLevels()}.
     * A value of 1 means log every event (no sampling).
     */
    public int getSamplingRate() {
        return samplingRate;
    }

    /**
     * The set of log levels subject to sampling. Events at these levels will be
     * sampled according to {@link #getSamplingRate()}.
     */
    public Set<LogLevel> getSampledLevels() {
        return sampledLevels;
    }

    public static final class Builder {
        private LogLevel minimumLevel = DEFAULT_MINIMUM_LEVEL;
        private int samplingRate = DEFAULT_SAMPLING_RATE;
        private Set<LogLevel> sampledLevels = DEFAULT_SAMPLED_LEVELS;

        private Builder() {
        }

        public Builder minimumLevel(LogLevel minimumLevel) {
            this.minimumLevel = minimumLevel;
            return this;
        }

        public Builder samplingRate(int samplingRate) {
            this.samplingRate = samplingRate;
            return this;
        }

        public Builder sampledLevels(Set<LogLevel> sampledLevels) {
            this.sampledLevels = sampledLevels;
            return this;
        }

        public AuditConfiguration build() {
            return new AuditConfiguration(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditConfiguration that = (AuditConfiguration) o;
        return samplingRate == that.samplingRate &&
                minimumLevel == that.minimumLevel &&
                Objects.equals(sampledLevels, that.sampledLevels);
    }

    @Override
    public int hashCode() {
        return Objects.hash(minimumLevel, samplingRate, sampledLevels);
    }

    @Override
    public String toString() {
        return "AuditConfiguration{" +
                "minimumLevel=" + minimumLevel +
                ", samplingRate=" + samplingRate +
                ", sampledLevels=" + sampledLevels +
                '}';
    }
}
