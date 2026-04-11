package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Value object tracking the version history of a DEK.
 *
 * <p>Key version history is essential for decrypting historical backups.
 * When a DEK is rotated, the old DEK must remain accessible so that data
 * encrypted with it can still be decrypted during a restore operation.
 */
public final class KeyVersionHistory {

    private final UUID dekId;
    private final UUID kekId;
    private final BoundedContext context;
    private final Environment environment;
    private final Instant createdAt;
    private final Instant rotatedAt;
    private final KeyStatus status;
    private final long encryptionCount;
    private final long bytesEncrypted;
    private final String keyNamespace;

    private KeyVersionHistory(Builder builder) {
        this.dekId = Objects.requireNonNull(builder.dekId, "DEK ID cannot be null");
        this.kekId = Objects.requireNonNull(builder.kekId, "KEK ID cannot be null");
        this.context = Objects.requireNonNull(builder.context, "Context cannot be null");
        this.environment = Objects.requireNonNull(builder.environment, "Environment cannot be null");
        this.createdAt = Objects.requireNonNull(builder.createdAt, "Created timestamp cannot be null");
        this.rotatedAt = builder.rotatedAt;
        this.status = Objects.requireNonNull(builder.status, "Status cannot be null");
        this.encryptionCount = builder.encryptionCount;
        this.bytesEncrypted = builder.bytesEncrypted;
        this.keyNamespace = builder.keyNamespace;
    }

    public static Builder builder() {
        return new Builder();
    }

    public UUID getDekId() {
        return dekId;
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

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getRotatedAt() {
        return rotatedAt;
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

    public String getKeyNamespace() {
        return keyNamespace;
    }

    /**
     * Returns true if this key version was active at the given timestamp.
     * A key was active from its creation until it was rotated (or is still active).
     */
    public boolean wasActiveAt(Instant timestamp) {
        Objects.requireNonNull(timestamp, "Timestamp cannot be null");
        if (timestamp.isBefore(createdAt)) {
            return false;
        }
        if (rotatedAt == null) {
            // Still active
            return status == KeyStatus.ACTIVE;
        }
        return !timestamp.isAfter(rotatedAt);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyVersionHistory that = (KeyVersionHistory) o;
        return Objects.equals(dekId, that.dekId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(dekId);
    }

    @Override
    public String toString() {
        return "KeyVersionHistory{dekId=" + dekId +
                ", kekId=" + kekId +
                ", context=" + context +
                ", status=" + status +
                ", createdAt=" + createdAt +
                ", rotatedAt=" + rotatedAt + "}";
    }

    public static final class Builder {
        private UUID dekId;
        private UUID kekId;
        private BoundedContext context;
        private Environment environment;
        private Instant createdAt;
        private Instant rotatedAt;
        private KeyStatus status;
        private long encryptionCount;
        private long bytesEncrypted;
        private String keyNamespace;

        private Builder() {}

        public Builder dekId(UUID dekId) { this.dekId = dekId; return this; }
        public Builder kekId(UUID kekId) { this.kekId = kekId; return this; }
        public Builder context(BoundedContext context) { this.context = context; return this; }
        public Builder environment(Environment environment) { this.environment = environment; return this; }
        public Builder createdAt(Instant createdAt) { this.createdAt = createdAt; return this; }
        public Builder rotatedAt(Instant rotatedAt) { this.rotatedAt = rotatedAt; return this; }
        public Builder status(KeyStatus status) { this.status = status; return this; }
        public Builder encryptionCount(long encryptionCount) { this.encryptionCount = encryptionCount; return this; }
        public Builder bytesEncrypted(long bytesEncrypted) { this.bytesEncrypted = bytesEncrypted; return this; }
        public Builder keyNamespace(String keyNamespace) { this.keyNamespace = keyNamespace; return this; }

        public KeyVersionHistory build() {
            return new KeyVersionHistory(this);
        }
    }
}
