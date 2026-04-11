package dev.vibeafrika.pcm.domain.encryption.config;

import dev.vibeafrika.pcm.domain.encryption.EncryptionAlgorithm;

import java.util.Objects;

/**
 * Settings that govern the encryption algorithm and IV generation strategy.
 *
 * <p>The {@link #counterPersistenceInterval} controls how often the IV counter
 * state is flushed to durable storage: every N increments (default 1000).
 */
public final class EncryptionSettings {

    /** Default number of counter increments between persistence flushes. */
    public static final int DEFAULT_COUNTER_PERSISTENCE_INTERVAL = 1000;

    private final EncryptionAlgorithm defaultAlgorithm;
    private final IvGenerationStrategy ivGeneration;
    private final int counterPersistenceInterval;

    private EncryptionSettings(Builder builder) {
        this.defaultAlgorithm = Objects.requireNonNull(builder.defaultAlgorithm, "defaultAlgorithm cannot be null");
        this.ivGeneration = Objects.requireNonNull(builder.ivGeneration, "ivGeneration cannot be null");
        if (builder.counterPersistenceInterval < 1) {
            throw new IllegalArgumentException("counterPersistenceInterval must be >= 1");
        }
        this.counterPersistenceInterval = builder.counterPersistenceInterval;
    }

    public static Builder builder() {
        return new Builder();
    }

    public EncryptionAlgorithm getDefaultAlgorithm() {
        return defaultAlgorithm;
    }

    public IvGenerationStrategy getIvGeneration() {
        return ivGeneration;
    }

    /**
     * Number of counter increments between persistence flushes.
     * The IV counter state is written to durable storage every N increments
     * to survive application restarts.
     */
    public int getCounterPersistenceInterval() {
        return counterPersistenceInterval;
    }

    public static final class Builder {
        private EncryptionAlgorithm defaultAlgorithm = EncryptionAlgorithm.AES_256_GCM;
        private IvGenerationStrategy ivGeneration = IvGenerationStrategy.COUNTER_BASED;
        private int counterPersistenceInterval = DEFAULT_COUNTER_PERSISTENCE_INTERVAL;

        private Builder() {}

        public Builder defaultAlgorithm(EncryptionAlgorithm defaultAlgorithm) {
            this.defaultAlgorithm = defaultAlgorithm;
            return this;
        }

        public Builder ivGeneration(IvGenerationStrategy ivGeneration) {
            this.ivGeneration = ivGeneration;
            return this;
        }

        public Builder counterPersistenceInterval(int counterPersistenceInterval) {
            this.counterPersistenceInterval = counterPersistenceInterval;
            return this;
        }

        public EncryptionSettings build() {
            return new EncryptionSettings(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptionSettings that = (EncryptionSettings) o;
        return counterPersistenceInterval == that.counterPersistenceInterval &&
                defaultAlgorithm == that.defaultAlgorithm &&
                ivGeneration == that.ivGeneration;
    }

    @Override
    public int hashCode() {
        return Objects.hash(defaultAlgorithm, ivGeneration, counterPersistenceInterval);
    }

    @Override
    public String toString() {
        return "EncryptionSettings{" +
                "defaultAlgorithm=" + defaultAlgorithm +
                ", ivGeneration=" + ivGeneration +
                ", counterPersistenceInterval=" + counterPersistenceInterval +
                '}';
    }
}
