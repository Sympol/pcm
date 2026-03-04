package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a decryption operation event for audit logging.
 * 
 * <p>This event captures metadata about a decryption operation including:
 * <ul>
 *   <li>Timestamp of the operation</li>
 *   <li>Bounded context where decryption occurred</li>
 *   <li>Service identity performing the decryption</li>
 *   <li>Key ID used for decryption</li>
 *   <li>Field identifier (but not the plaintext value)</li>
 *   <li>Success status</li>
 *   <li>Error code if operation failed</li>
 *   <li>Additional metadata</li>
 * </ul>
 * 
 */
public final class DecryptionEvent {
    private final Instant timestamp;
    private final BoundedContext context;
    private final String serviceIdentity;
    private final String userContext;
    private final UUID keyId;
    private final String fieldIdentifier;
    private final boolean success;
    private final String errorCode;
    private final Map<String, Object> metadata;

    private DecryptionEvent(Builder builder) {
        this.timestamp = Objects.requireNonNull(builder.timestamp, "Timestamp cannot be null");
        this.context = Objects.requireNonNull(builder.context, "Context cannot be null");
        this.serviceIdentity = Objects.requireNonNull(builder.serviceIdentity, "Service identity cannot be null");
        this.userContext = builder.userContext;
        this.keyId = builder.keyId;
        this.fieldIdentifier = builder.fieldIdentifier;
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

    public String getUserContext() {
        return userContext;
    }

    public UUID getKeyId() {
        return keyId;
    }

    public String getFieldIdentifier() {
        return fieldIdentifier;
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
        private String userContext;
        private UUID keyId;
        private String fieldIdentifier;
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

        public Builder userContext(String userContext) {
            this.userContext = userContext;
            return this;
        }

        public Builder keyId(UUID keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder fieldIdentifier(String fieldIdentifier) {
            this.fieldIdentifier = fieldIdentifier;
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

        public DecryptionEvent build() {
            return new DecryptionEvent(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DecryptionEvent that = (DecryptionEvent) o;
        return success == that.success &&
                Objects.equals(timestamp, that.timestamp) &&
                context == that.context &&
                Objects.equals(serviceIdentity, that.serviceIdentity) &&
                Objects.equals(userContext, that.userContext) &&
                Objects.equals(keyId, that.keyId) &&
                Objects.equals(fieldIdentifier, that.fieldIdentifier) &&
                Objects.equals(errorCode, that.errorCode) &&
                Objects.equals(metadata, that.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(timestamp, context, serviceIdentity, userContext, keyId, 
                fieldIdentifier, success, errorCode, metadata);
    }

    @Override
    public String toString() {
        return "DecryptionEvent{" +
                "timestamp=" + timestamp +
                ", context=" + context +
                ", serviceIdentity='" + serviceIdentity + '\'' +
                ", userContext='" + userContext + '\'' +
                ", keyId=" + keyId +
                ", fieldIdentifier='" + fieldIdentifier + '\'' +
                ", success=" + success +
                ", errorCode='" + errorCode + '\'' +
                ", metadata=" + metadata +
                '}';
    }
}
