package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Certificate proving cryptographic erasure of user data.
 * Generated when a user-specific DEK is deleted for GDPR compliance.
 */
public final class DeletionCertificate {
    private final UUID keyId;
    private final String userId;
    private final BoundedContext context;
    private final Instant deletedAt;
    private final String signature;

    private DeletionCertificate(UUID keyId, String userId, BoundedContext context, 
                                Instant deletedAt, String signature) {
        this.keyId = Objects.requireNonNull(keyId, "Key ID cannot be null");
        this.userId = Objects.requireNonNull(userId, "User ID cannot be null");
        this.context = Objects.requireNonNull(context, "Context cannot be null");
        this.deletedAt = Objects.requireNonNull(deletedAt, "Deletion timestamp cannot be null");
        this.signature = Objects.requireNonNull(signature, "Signature cannot be null");
    }

    public static DeletionCertificate of(UUID keyId, String userId, BoundedContext context,
                                         Instant deletedAt, String signature) {
        return new DeletionCertificate(keyId, userId, context, deletedAt, signature);
    }

    public UUID getKeyId() {
        return keyId;
    }

    public String getUserId() {
        return userId;
    }

    public BoundedContext getContext() {
        return context;
    }

    public Instant getDeletedAt() {
        return deletedAt;
    }

    public String getSignature() {
        return signature;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DeletionCertificate that = (DeletionCertificate) o;
        return Objects.equals(keyId, that.keyId) &&
                Objects.equals(userId, that.userId) &&
                context == that.context &&
                Objects.equals(deletedAt, that.deletedAt) &&
                Objects.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId, userId, context, deletedAt, signature);
    }

    @Override
    public String toString() {
        return "DeletionCertificate{" +
                "keyId=" + keyId +
                ", userId='" + userId + '\'' +
                ", context=" + context +
                ", deletedAt=" + deletedAt +
                ", signature='" + signature + '\'' +
                '}';
    }
}
