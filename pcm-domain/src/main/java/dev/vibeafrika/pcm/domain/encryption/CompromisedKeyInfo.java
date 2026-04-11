package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Value object describing a compromised encryption key and the circumstances of its compromise.
 *
 * <p>This record captures the key identifier, the context it belongs to, when the compromise
 * was detected, and a description of how the compromise was identified.
 */
public final class CompromisedKeyInfo {

    private final UUID keyId;
    private final BoundedContext context;
    private final Instant detectedAt;
    private final String compromiseDescription;

    private CompromisedKeyInfo(UUID keyId, BoundedContext context, Instant detectedAt,
                                String compromiseDescription) {
        this.keyId = Objects.requireNonNull(keyId, "Key ID cannot be null");
        this.context = Objects.requireNonNull(context, "Context cannot be null");
        this.detectedAt = Objects.requireNonNull(detectedAt, "Detection timestamp cannot be null");
        this.compromiseDescription = Objects.requireNonNull(compromiseDescription,
                "Compromise description cannot be null");
    }

    public static CompromisedKeyInfo of(UUID keyId, BoundedContext context, Instant detectedAt,
                                         String compromiseDescription) {
        return new CompromisedKeyInfo(keyId, context, detectedAt, compromiseDescription);
    }

    public UUID getKeyId() {
        return keyId;
    }

    public BoundedContext getContext() {
        return context;
    }

    public Instant getDetectedAt() {
        return detectedAt;
    }

    public String getCompromiseDescription() {
        return compromiseDescription;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CompromisedKeyInfo that = (CompromisedKeyInfo) o;
        return Objects.equals(keyId, that.keyId) &&
                context == that.context &&
                Objects.equals(detectedAt, that.detectedAt) &&
                Objects.equals(compromiseDescription, that.compromiseDescription);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId, context, detectedAt, compromiseDescription);
    }

    @Override
    public String toString() {
        return "CompromisedKeyInfo{keyId=" + keyId +
                ", context=" + context +
                ", detectedAt=" + detectedAt +
                ", compromiseDescription='" + compromiseDescription + "'}";
    }
}
