package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Represents a security event for audit logging.
 * 
 * <p>This event captures metadata about security-related incidents including:
 * <ul>
 *   <li>Timestamp of the event</li>
 *   <li>Bounded context where the event occurred</li>
 *   <li>Service identity involved in the event</li>
 *   <li>Event type (tampering detected, unauthorized access, etc.)</li>
 *   <li>Severity level (CRITICAL, HIGH, MEDIUM, LOW)</li>
 *   <li>Key ID involved (if applicable)</li>
 *   <li>Field identifier (if applicable)</li>
 *   <li>Description of the security event</li>
 *   <li>Additional metadata</li>
 * </ul>
 * 
 */
public final class SecurityEvent {
    private final Instant timestamp;
    private final BoundedContext context;
    private final String serviceIdentity;
    private final String userContext;
    private final String eventType;
    private final String severity;
    private final UUID keyId;
    private final String fieldIdentifier;
    private final String description;
    private final Map<String, Object> metadata;

    private SecurityEvent(Builder builder) {
        this.timestamp = Objects.requireNonNull(builder.timestamp, "Timestamp cannot be null");
        this.context = Objects.requireNonNull(builder.context, "Context cannot be null");
        this.serviceIdentity = Objects.requireNonNull(builder.serviceIdentity, "Service identity cannot be null");
        this.userContext = builder.userContext;
        this.eventType = Objects.requireNonNull(builder.eventType, "Event type cannot be null");
        this.severity = Objects.requireNonNull(builder.severity, "Severity cannot be null");
        this.keyId = builder.keyId;
        this.fieldIdentifier = builder.fieldIdentifier;
        this.description = builder.description;
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

    public String getEventType() {
        return eventType;
    }

    public String getSeverity() {
        return severity;
    }

    public UUID getKeyId() {
        return keyId;
    }

    public String getFieldIdentifier() {
        return fieldIdentifier;
    }

    public String getDescription() {
        return description;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public static final class Builder {
        private Instant timestamp;
        private BoundedContext context;
        private String serviceIdentity;
        private String userContext;
        private String eventType;
        private String severity;
        private UUID keyId;
        private String fieldIdentifier;
        private String description;
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

        public Builder eventType(String eventType) {
            this.eventType = eventType;
            return this;
        }

        public Builder severity(String severity) {
            this.severity = severity;
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

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }

        public SecurityEvent build() {
            return new SecurityEvent(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityEvent that = (SecurityEvent) o;
        return Objects.equals(timestamp, that.timestamp) &&
                context == that.context &&
                Objects.equals(serviceIdentity, that.serviceIdentity) &&
                Objects.equals(userContext, that.userContext) &&
                Objects.equals(eventType, that.eventType) &&
                Objects.equals(severity, that.severity) &&
                Objects.equals(keyId, that.keyId) &&
                Objects.equals(fieldIdentifier, that.fieldIdentifier) &&
                Objects.equals(description, that.description) &&
                Objects.equals(metadata, that.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(timestamp, context, serviceIdentity, userContext, eventType, 
                severity, keyId, fieldIdentifier, description, metadata);
    }

    @Override
    public String toString() {
        return "SecurityEvent{" +
                "timestamp=" + timestamp +
                ", context=" + context +
                ", serviceIdentity='" + serviceIdentity + '\'' +
                ", userContext='" + userContext + '\'' +
                ", eventType='" + eventType + '\'' +
                ", severity='" + severity + '\'' +
                ", keyId=" + keyId +
                ", fieldIdentifier='" + fieldIdentifier + '\'' +
                ", description='" + description + '\'' +
                ", metadata=" + metadata +
                '}';
    }
}
