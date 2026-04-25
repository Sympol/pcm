package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Metadata for a non-cryptographic secret stored in KMS.
 *
 * <p>Mirrors the structure of {@link DEKWithMetadata} so that secrets are managed
 * with the same lifecycle, rotation schedules, and access control as DEKs.
 */
public final class SecretMetadata {

    private final UUID secretId;
    private final String secretName;
    private final SecretType secretType;
    private final BoundedContext context;
    private final Environment environment;
    private final Instant createdAt;
    private final Instant rotatedAt;
    private final KeyStatus status;

    private SecretMetadata(Builder builder) {
        this.secretId = Objects.requireNonNull(builder.secretId, "Secret ID cannot be null");
        this.secretName = Objects.requireNonNull(builder.secretName, "Secret name cannot be null");
        this.secretType = Objects.requireNonNull(builder.secretType, "Secret type cannot be null");
        this.context = Objects.requireNonNull(builder.context, "Context cannot be null");
        this.environment = Objects.requireNonNull(builder.environment, "Environment cannot be null");
        this.createdAt = Objects.requireNonNull(builder.createdAt, "Created timestamp cannot be null");
        this.rotatedAt = builder.rotatedAt;
        this.status = Objects.requireNonNull(builder.status, "Status cannot be null");
    }

    public static Builder builder() {
        return new Builder();
    }

    public UUID getSecretId() { return secretId; }
    public String getSecretName() { return secretName; }
    public SecretType getSecretType() { return secretType; }
    public BoundedContext getContext() { return context; }
    public Environment getEnvironment() { return environment; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getRotatedAt() { return rotatedAt; }
    public KeyStatus getStatus() { return status; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecretMetadata that = (SecretMetadata) o;
        return Objects.equals(secretId, that.secretId) &&
               Objects.equals(secretName, that.secretName) &&
               secretType == that.secretType &&
               context == that.context &&
               environment == that.environment &&
               Objects.equals(createdAt, that.createdAt) &&
               Objects.equals(rotatedAt, that.rotatedAt) &&
               status == that.status;
    }

    @Override
    public int hashCode() {
        return Objects.hash(secretId, secretName, secretType, context, environment,
                createdAt, rotatedAt, status);
    }

    @Override
    public String toString() {
        return "SecretMetadata{secretId=" + secretId +
               ", secretName=" + secretName +
               ", secretType=" + secretType +
               ", context=" + context +
               ", environment=" + environment +
               ", createdAt=" + createdAt +
               ", rotatedAt=" + rotatedAt +
               ", status=" + status + "}";
    }

    public static final class Builder {
        private UUID secretId;
        private String secretName;
        private SecretType secretType;
        private BoundedContext context;
        private Environment environment;
        private Instant createdAt;
        private Instant rotatedAt;
        private KeyStatus status;

        private Builder() {}

        public Builder secretId(UUID secretId) { this.secretId = secretId; return this; }
        public Builder secretName(String secretName) { this.secretName = secretName; return this; }
        public Builder secretType(SecretType secretType) { this.secretType = secretType; return this; }
        public Builder context(BoundedContext context) { this.context = context; return this; }
        public Builder environment(Environment environment) { this.environment = environment; return this; }
        public Builder createdAt(Instant createdAt) { this.createdAt = createdAt; return this; }
        public Builder rotatedAt(Instant rotatedAt) { this.rotatedAt = rotatedAt; return this; }
        public Builder status(KeyStatus status) { this.status = status; return this; }

        public SecretMetadata build() { return new SecretMetadata(this); }
    }
}
