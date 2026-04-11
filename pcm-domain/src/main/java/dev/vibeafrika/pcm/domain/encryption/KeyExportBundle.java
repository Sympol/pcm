package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Value object representing a bundle of KEKs exported and encrypted with an offline master key.
 *
 * <p>The offline master key is stored in a hardware security module or secure offline storage.
 * KEKs in this bundle are encrypted with the offline master key so they can be safely stored
 * in cold storage for disaster recovery.
 */
public final class KeyExportBundle {

    private final UUID bundleId;
    private final String offlineMasterKeyId;
    private final List<ExportedKEK> exportedKEKs;
    private final Instant exportedAt;
    private final Environment environment;

    private KeyExportBundle(UUID bundleId, String offlineMasterKeyId,
                            List<ExportedKEK> exportedKEKs, Instant exportedAt,
                            Environment environment) {
        this.bundleId = Objects.requireNonNull(bundleId, "Bundle ID cannot be null");
        this.offlineMasterKeyId = Objects.requireNonNull(offlineMasterKeyId, "Offline master key ID cannot be null");
        this.exportedKEKs = Collections.unmodifiableList(
                Objects.requireNonNull(exportedKEKs, "Exported KEKs cannot be null"));
        this.exportedAt = Objects.requireNonNull(exportedAt, "Export timestamp cannot be null");
        this.environment = Objects.requireNonNull(environment, "Environment cannot be null");
    }

    public static KeyExportBundle of(UUID bundleId, String offlineMasterKeyId,
                                     List<ExportedKEK> exportedKEKs, Instant exportedAt,
                                     Environment environment) {
        return new KeyExportBundle(bundleId, offlineMasterKeyId, exportedKEKs, exportedAt, environment);
    }

    public UUID getBundleId() {
        return bundleId;
    }

    public String getOfflineMasterKeyId() {
        return offlineMasterKeyId;
    }

    /** Returns an unmodifiable list of KEKs encrypted with the offline master key. */
    public List<ExportedKEK> getExportedKEKs() {
        return exportedKEKs;
    }

    public Instant getExportedAt() {
        return exportedAt;
    }

    public Environment getEnvironment() {
        return environment;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyExportBundle that = (KeyExportBundle) o;
        return Objects.equals(bundleId, that.bundleId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bundleId);
    }

    @Override
    public String toString() {
        return "KeyExportBundle{bundleId=" + bundleId +
                ", offlineMasterKeyId=" + offlineMasterKeyId +
                ", kekCount=" + exportedKEKs.size() +
                ", exportedAt=" + exportedAt +
                ", environment=" + environment + "}";
    }

    /**
     * Represents a single KEK encrypted with the offline master key.
     */
    public static final class ExportedKEK {
        private final UUID kekId;
        private final BoundedContext context;
        private final byte[] encryptedKEKMaterial;
        private final Instant createdAt;
        private final KeyStatus status;

        private ExportedKEK(UUID kekId, BoundedContext context, byte[] encryptedKEKMaterial,
                            Instant createdAt, KeyStatus status) {
            this.kekId = Objects.requireNonNull(kekId, "KEK ID cannot be null");
            this.context = Objects.requireNonNull(context, "Context cannot be null");
            this.encryptedKEKMaterial = Objects.requireNonNull(encryptedKEKMaterial,
                    "Encrypted KEK material cannot be null").clone();
            this.createdAt = Objects.requireNonNull(createdAt, "Created timestamp cannot be null");
            this.status = Objects.requireNonNull(status, "Status cannot be null");
        }

        public static ExportedKEK of(UUID kekId, BoundedContext context, byte[] encryptedKEKMaterial,
                                     Instant createdAt, KeyStatus status) {
            return new ExportedKEK(kekId, context, encryptedKEKMaterial, createdAt, status);
        }

        public UUID getKekId() { return kekId; }
        public BoundedContext getContext() { return context; }
        /** Returns a copy of the KEK material encrypted with the offline master key. */
        public byte[] getEncryptedKEKMaterial() { return encryptedKEKMaterial.clone(); }
        public Instant getCreatedAt() { return createdAt; }
        public KeyStatus getStatus() { return status; }

        @Override
        public String toString() {
            return "ExportedKEK{kekId=" + kekId + ", context=" + context + ", status=" + status + "}";
        }
    }
}
