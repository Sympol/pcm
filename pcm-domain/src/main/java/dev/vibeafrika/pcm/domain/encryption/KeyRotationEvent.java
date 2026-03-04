package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a key rotation event for audit logging.
 * 
 * <p>This event captures metadata about a key rotation operation including:
 * <ul>
 *   <li>Timestamp of the rotation</li>
 *   <li>Bounded context where rotation occurred</li>
 *   <li>Service identity performing the rotation</li>
 *   <li>Old key ID being rotated</li>
 *   <li>New key ID replacing the old key</li>
 *   <li>Key type (DEK or KEK)</li>
 *   <li>Rotation reason (scheduled, emergency, compliance, etc.)</li>
 *   <li>Success status</li>
 *   <li>Error code if operation failed</li>
 *   <li>Additional metadata</li>
 * </ul>
 * 
 */
public final class KeyRotationEvent {
    private final Instant timestamp;
    private final BoundedContext context;
    private final String serviceIdentity;
    private final UUID oldKeyId;
    private final UUID newKeyId;
    private final String keyType;
    private final String rotationReason;
    private final boolean success;
    private final String errorCode;
    private final Map<String, Object> metadata;

    private KeyRotationEvent(Builder builder) {
        this.timestamp = Objects.requireNonNull(builder.timestamp, "Timestamp cannot be null");
        this.context = Objects.requireNonNull(builder.context, "Context cannot be null");
        this.serviceIdentity = Objects.requireNonNull(builder.serviceIdentity, "Service identity cannot be null");
        this.oldKeyId = builder.oldKeyId;
        this.newKeyId = builder.newKeyId;
        this.keyType = builder.keyType;
        this.rotationReason = builder.rotationReason;
        this.success = builder.success;
        this.errorCode = builder.errorCode;
        this.metadata = builder.metadata != null ? Map.copyOf(builder.metadata) : Map.of();
    }

    public static Builder builder() {
        return new Builder();
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public BoundedContext getContext() {
        return context;
    }

    public String getServiceIdentity() {
        return serviceIdentity;
    }

    public UUID getOldKeyId() {
        return oldKeyId;
    }

    public UUID getNewKeyId() {
        return newKeyId;
    }

    public String getKeyType() {
        return keyType;
    }

    public String getRotationReason() {
        return rotationReason;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public static final class Builder {
        private Instant timestamp;
        private BoundedContext context;
        private String serviceIdentity;
        private UUID oldKeyId;
        private UUID newKeyId;
        private String keyType;
        private String rotationReason;
        private boolean success;
        private String errorCode;
        private Map<String, Object> metadata;

        private Builder() {
        }

        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder context(BoundedContext context) {
            this.context = context;
            return this;
        }

        public Builder serviceIdentity(String serviceIdentity) {
            this.serviceIdentity = serviceIdentity;
            return this;
        }

        public Builder oldKeyId(UUID oldKeyId) {
            this.oldKeyId = oldKeyId;
            return this;
        }

        public Builder newKeyId(UUID newKeyId) {
            this.newKeyId = newKeyId;
            return this;
        }

        public Builder keyType(String keyType) {
            this.keyType = keyType;
            return this;
        }

        public Builder rotationReason(String rotationReason) {
            this.rotationReason = rotationReason;
            return this;
        }

        public Builder success(boolean success) {
            this.success = success;
            return this;
        }

        public Builder errorCode(String errorCode) {
            this.errorCode = errorCode;
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        public KeyRotationEvent build() {
            return new KeyRotationEvent(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyRotationEvent that = (KeyRotationEvent) o;
        return success == that.success &&
                Objects.equals(timestamp, that.timestamp) &&
                context == that.context &&
                Objects.equals(serviceIdentity, that.serviceIdentity) &&
                Objects.equals(oldKeyId, that.oldKeyId) &&
                Objects.equals(newKeyId, that.newKeyId) &&
                Objects.equals(keyType, that.keyType) &&
                Objects.equals(rotationReason, that.rotationReason) &&
                Objects.equals(errorCode, that.errorCode) &&
                Objects.equals(metadata, that.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(timestamp, context, serviceIdentity, oldKeyId, newKeyId, 
                keyType, rotationReason, success, errorCode, metadata);
    }

    @Override
    public String toString() {
        return "KeyRotationEvent{" +
                "timestamp=" + timestamp +
                ", context=" + context +
                ", serviceIdentity='" + serviceIdentity + '\'' +
                ", oldKeyId=" + oldKeyId +
                ", newKeyId=" + newKeyId +
                ", keyType='" + keyType + '\'' +
                ", rotationReason='" + rotationReason + '\'' +
                ", success=" + success +
                ", errorCode='" + errorCode + '\'' +
                ", metadata=" + metadata +
                '}';
    }
}
