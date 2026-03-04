package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Value object representing a DEK with its associated metadata.
 * Used by KeyManager to return DEKs with context information.
 */
public final class DEKWithMetadata {
    private final DEK dek;
    private final UUID keyId;
    private final UUID kekId;
    private final BoundedContext context;
    private final Environment environment;
    private final EncryptionAlgorithm algorithm;
    private final Instant createdAt;
    private final Instant rotatedAt;
    private final KeyStatus status;
    private final long encryptionCount;
    private final long bytesEncrypted;

    private DEKWithMetadata(Builder builder) {
        this.dek = Objects.requireNonNull(builder.dek, "DEK cannot be null");
        this.keyId = Objects.requireNonNull(builder.keyId, "Key ID cannot be null");
        this.kekId = Objects.requireNonNull(builder.kekId, "KEK ID cannot be null");
        this.context = Objects.requireNonNull(builder.context, "Context cannot be null");
        this.environment = Objects.requireNonNull(builder.environment, "Environment cannot be null");
        this.algorithm = Objects.requireNonNull(builder.algorithm, "Algorithm cannot be null");
        this.createdAt = Objects.requireNonNull(builder.createdAt, "Created timestamp cannot be null");
        this.rotatedAt = builder.rotatedAt;
        this.status = Objects.requireNonNull(builder.status, "Status cannot be null");
        this.encryptionCount = builder.encryptionCount;
        this.bytesEncrypted = builder.bytesEncrypted;
    }

    public static Builder builder() {
        return new Builder();
    }

    public DEK getDek() {
        return dek;
    }

    public UUID getKeyId() {
        return keyId;
    }

    public UUID getKekId() {
        return kekId;
    }

    public BoundedContext getContext() {
        return context;
    }

    public Environment getEnvironment() {
        return environment;
    }

    public EncryptionAlgorithm getAlgorithm() {
        return algorithm;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Optional<Instant> getRotatedAt() {
        return Optional.ofNullable(rotatedAt);
    }

    public KeyStatus getStatus() {
        return status;
    }

    public long getEncryptionCount() {
        return encryptionCount;
    }

    public long getBytesEncrypted() {
        return bytesEncrypted;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DEKWithMetadata that = (DEKWithMetadata) o;
        return encryptionCount == that.encryptionCount &&
                bytesEncrypted == that.bytesEncrypted &&
                Objects.equals(dek, that.dek) &&
                Objects.equals(keyId, that.keyId) &&
                Objects.equals(kekId, that.kekId) &&
                context == that.context &&
                environment == that.environment &&
                algorithm == that.algorithm &&
                Objects.equals(createdAt, that.createdAt) &&
                Objects.equals(rotatedAt, that.rotatedAt) &&
                status == that.status;
    }

    @Override
    public int hashCode() {
        return Objects.hash(dek, keyId, kekId, context, environment, algorithm,
                createdAt, rotatedAt, status, encryptionCount, bytesEncrypted);
    }

    @Override
    public String toString() {
        return "DEKWithMetadata{" +
                "keyId=" + keyId +
                ", kekId=" + kekId +
                ", context=" + context +
                ", environment=" + environment +
                ", algorithm=" + algorithm +
                ", createdAt=" + createdAt +
                ", rotatedAt=" + rotatedAt +
                ", status=" + status +
                ", encryptionCount=" + encryptionCount +
                ", bytesEncrypted=" + bytesEncrypted +
                '}';
    }

    public static final class Builder {
        private DEK dek;
        private UUID keyId;
        private UUID kekId;
        private BoundedContext context;
        private Environment environment;
        private EncryptionAlgorithm algorithm;
        private Instant createdAt;
        private Instant rotatedAt;
        private KeyStatus status;
        private long encryptionCount;
        private long bytesEncrypted;

        private Builder() {
        }

        public Builder dek(DEK dek) {
            this.dek = dek;
            return this;
        }

        public Builder keyId(UUID keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder kekId(UUID kekId) {
            this.kekId = kekId;
            return this;
        }

        public Builder context(BoundedContext context) {
            this.context = context;
            return this;
        }

        public Builder environment(Environment environment) {
            this.environment = environment;
            return this;
        }

        public Builder algorithm(EncryptionAlgorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder createdAt(Instant createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public Builder rotatedAt(Instant rotatedAt) {
            this.rotatedAt = rotatedAt;
            return this;
        }

        public Builder status(KeyStatus status) {
            this.status = status;
            return this;
        }

        public Builder encryptionCount(long encryptionCount) {
            this.encryptionCount = encryptionCount;
            return this;
        }

        public Builder bytesEncrypted(long bytesEncrypted) {
            this.bytesEncrypted = bytesEncrypted;
            return this;
        }

        public DEKWithMetadata build() {
            return new DEKWithMetadata(this);
        }
    }
}
