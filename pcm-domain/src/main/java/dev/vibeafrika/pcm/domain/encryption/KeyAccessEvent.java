package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a key access event for audit logging.
 * 
 * <p>This event captures metadata about key access operations including:
 * <ul>
 *   <li>Timestamp of the access</li>
 *   <li>Bounded context where access occurred</li>
 *   <li>Service identity accessing the key</li>
 *   <li>Key ID being accessed</li>
 *   <li>Key type (DEK or KEK)</li>
 *   <li>Access type (retrieve, cache_hit, cache_miss, etc.)</li>
 *   <li>Success status</li>
 *   <li>Error code if operation failed</li>
 *   <li>Additional metadata</li>
 * </ul>
 * 
 */
public final class KeyAccessEvent {
    private final Instant timestamp;
    private final BoundedContext context;
    private final String serviceIdentity;
    private final UUID keyId;
    private final String keyType;
    private final String accessType;
    private final boolean success;
    private final String errorCode;
    private final Map<String, Object> metadata;

    private KeyAccessEvent(Builder builder) {
        this.timestamp = Objects.requireNonNull(builder.timestamp, "Timestamp cannot be null");
        this.context = Objects.requireNonNull(builder.context, "Context cannot be null");
        this.serviceIdentity = Objects.requireNonNull(builder.serviceIdentity, "Service identity cannot be null");
        this.keyId = builder.keyId;
        this.keyType = builder.keyType;
        this.accessType = builder.accessType;
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

    public UUID getKeyId() {
        return keyId;
    }

    public String getKeyType() {
        return keyType;
    }

    public String getAccessType() {
        return accessType;
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
        private UUID keyId;
        private String keyType;
        private String accessType;
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

        public Builder keyId(UUID keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder keyType(String keyType) {
            this.keyType = keyType;
            return this;
        }

        public Builder accessType(String accessType) {
            this.accessType = accessType;
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

        public KeyAccessEvent build() {
            return new KeyAccessEvent(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyAccessEvent that = (KeyAccessEvent) o;
        return success == that.success &&
                Objects.equals(timestamp, that.timestamp) &&
                context == that.context &&
                Objects.equals(serviceIdentity, that.serviceIdentity) &&
                Objects.equals(keyId, that.keyId) &&
                Objects.equals(keyType, that.keyType) &&
                Objects.equals(accessType, that.accessType) &&
                Objects.equals(errorCode, that.errorCode) &&
                Objects.equals(metadata, that.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(timestamp, context, serviceIdentity, keyId, keyType, 
                accessType, success, errorCode, metadata);
    }

    @Override
    public String toString() {
        return "KeyAccessEvent{" +
                "timestamp=" + timestamp +
                ", context=" + context +
                ", serviceIdentity='" + serviceIdentity + '\'' +
                ", keyId=" + keyId +
                ", keyType='" + keyType + '\'' +
                ", accessType='" + accessType + '\'' +
                ", success=" + success +
                ", errorCode='" + errorCode + '\'' +
                ", metadata=" + metadata +
                '}';
    }
}
