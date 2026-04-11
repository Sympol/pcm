package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Represents an audit log access event for audit logging.
 *
 * <p>This event captures metadata about audit log access operations including:
 * <ul>
 *   <li>Timestamp of the access</li>
 *   <li>Bounded context where access occurred</li>
 *   <li>Service identity of the accessor</li>
 *   <li>Accessor identity (who accessed the audit logs)</li>
 *   <li>What was accessed (e.g. query parameters, time range, event types)</li>
 *   <li>Success status</li>
 *   <li>Error code if operation failed</li>
 *   <li>Additional metadata</li>
 * </ul>
 *
 * <p>WHEN audit log access occurs, THE Audit_Logger SHALL log
 * the access event with accessor identity and timestamp.
 */
public final class AuditLogAccessEvent {
    private final Instant timestamp;
    private final BoundedContext context;
    private final String serviceIdentity;
    private final String accessorIdentity;
    private final String accessDescription;
    private final boolean success;
    private final String errorCode;
    private final Map<String, Object> metadata;

    private AuditLogAccessEvent(Builder builder) {
        this.timestamp = Objects.requireNonNull(builder.timestamp, "Timestamp cannot be null");
        this.context = Objects.requireNonNull(builder.context, "Context cannot be null");
        this.serviceIdentity = Objects.requireNonNull(builder.serviceIdentity, "Service identity cannot be null");
        this.accessorIdentity = Objects.requireNonNull(builder.accessorIdentity, "Accessor identity cannot be null");
        this.accessDescription = builder.accessDescription;
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

    /** Identity of the entity that accessed the audit logs (e.g. user ID, service name, role). */
    public String getAccessorIdentity() {
        return accessorIdentity;
    }

    /** Human-readable description of what was accessed (e.g. query range, event types). */
    public String getAccessDescription() {
        return accessDescription;
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
        private String accessorIdentity;
        private String accessDescription;
        private boolean success = true;
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

        public Builder accessorIdentity(String accessorIdentity) {
            this.accessorIdentity = accessorIdentity;
            return this;
        }

        public Builder accessDescription(String accessDescription) {
            this.accessDescription = accessDescription;
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

        public AuditLogAccessEvent build() {
            return new AuditLogAccessEvent(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditLogAccessEvent that = (AuditLogAccessEvent) o;
        return success == that.success &&
                Objects.equals(timestamp, that.timestamp) &&
                context == that.context &&
                Objects.equals(serviceIdentity, that.serviceIdentity) &&
                Objects.equals(accessorIdentity, that.accessorIdentity) &&
                Objects.equals(accessDescription, that.accessDescription) &&
                Objects.equals(errorCode, that.errorCode) &&
                Objects.equals(metadata, that.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(timestamp, context, serviceIdentity, accessorIdentity,
                accessDescription, success, errorCode, metadata);
    }

    @Override
    public String toString() {
        return "AuditLogAccessEvent{" +
                "timestamp=" + timestamp +
                ", context=" + context +
                ", serviceIdentity='" + serviceIdentity + '\'' +
                ", accessorIdentity='" + accessorIdentity + '\'' +
                ", accessDescription='" + accessDescription + '\'' +
                ", success=" + success +
                ", errorCode='" + errorCode + '\'' +
                ", metadata=" + metadata +
                '}';
    }
}
