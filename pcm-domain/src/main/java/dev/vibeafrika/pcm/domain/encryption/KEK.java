package dev.vibeafrika.pcm.domain.encryption;

import java.util.Objects;
import java.util.UUID;

/**
 * Value object representing a Key Encryption Key (KEK) identifier.
 * KEKs remain in the KMS/HSM and are used to encrypt DEKs.
 * This class only holds the identifier, not the actual key material.
 */
public final class KEK {
    private final UUID keyId;
    private final BoundedContext context;

    private KEK(UUID keyId, BoundedContext context) {
        this.keyId = keyId;
        this.context = context;
    }

    public static KEK of(UUID keyId, BoundedContext context) {
        Objects.requireNonNull(keyId, "KEK key ID cannot be null");
        Objects.requireNonNull(context, "KEK context cannot be null");
        return new KEK(keyId, context);
    }

    public UUID getKeyId() {
        return keyId;
    }

    public BoundedContext getContext() {
        return context;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KEK kek = (KEK) o;
        return Objects.equals(keyId, kek.keyId) && context == kek.context;
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId, context);
    }

    @Override
    public String toString() {
        return "KEK{keyId=" + keyId + ", context=" + context + "}";
    }
}
