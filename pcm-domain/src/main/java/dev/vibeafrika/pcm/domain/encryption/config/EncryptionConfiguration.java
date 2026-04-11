package dev.vibeafrika.pcm.domain.encryption.config;

import java.util.Objects;

/**
 * Top-level configuration model for the PII encryption subsystem.
 *
 * <p>Aggregates all sub-configurations :
 * <ul>
 *   <li>{@link KMSConfiguration} – KMS provider, endpoint, authentication, and FIPS level.</li>
 *   <li>{@link EncryptionSettings} – algorithm, IV generation strategy, and counter persistence.</li>
 *   <li>{@link KeyRotationPolicy} – DEK/KEK rotation schedules and emergency rotation SLA.</li>
 *   <li>{@link CachingPolicy} – DEK cache TTL, max size, eviction policy, and secure memory.</li>
 *   <li>{@link AuditConfigurationModel} – audit level, retention, encryption, signing, and sampling.</li>
 *   <li>{@link NetworkConfiguration} – mTLS, private-subnet restriction, IP allow-list, circuit breaker.</li>
 * </ul>
 *
 * <p>This class is intentionally framework-agnostic (no Spring or Jakarta annotations)
 * so it can live in the domain layer and be used by both the configuration parser
 * and the infrastructure layer without introducing framework dependencies.
 */
public final class EncryptionConfiguration {

    private final KMSConfiguration kms;
    private final EncryptionSettings encryption;
    private final KeyRotationPolicy keyRotation;
    private final CachingPolicy caching;
    private final AuditConfigurationModel audit;
    private final NetworkConfiguration network;

    private EncryptionConfiguration(Builder builder) {
        this.kms = Objects.requireNonNull(builder.kms, "kms cannot be null");
        this.encryption = Objects.requireNonNull(builder.encryption, "encryption cannot be null");
        this.keyRotation = Objects.requireNonNull(builder.keyRotation, "keyRotation cannot be null");
        this.caching = Objects.requireNonNull(builder.caching, "caching cannot be null");
        this.audit = Objects.requireNonNull(builder.audit, "audit cannot be null");
        this.network = Objects.requireNonNull(builder.network, "network cannot be null");
    }

    public static Builder builder() {
        return new Builder();
    }

    public KMSConfiguration getKms() {
        return kms;
    }

    public EncryptionSettings getEncryption() {
        return encryption;
    }

    public KeyRotationPolicy getKeyRotation() {
        return keyRotation;
    }

    public CachingPolicy getCaching() {
        return caching;
    }

    public AuditConfigurationModel getAudit() {
        return audit;
    }

    public NetworkConfiguration getNetwork() {
        return network;
    }

    public static final class Builder {
        private KMSConfiguration kms;
        private EncryptionSettings encryption;
        private KeyRotationPolicy keyRotation;
        private CachingPolicy caching;
        private AuditConfigurationModel audit;
        private NetworkConfiguration network;

        private Builder() {}

        public Builder kms(KMSConfiguration kms) {
            this.kms = kms;
            return this;
        }

        public Builder encryption(EncryptionSettings encryption) {
            this.encryption = encryption;
            return this;
        }

        public Builder keyRotation(KeyRotationPolicy keyRotation) {
            this.keyRotation = keyRotation;
            return this;
        }

        public Builder caching(CachingPolicy caching) {
            this.caching = caching;
            return this;
        }

        public Builder audit(AuditConfigurationModel audit) {
            this.audit = audit;
            return this;
        }

        public Builder network(NetworkConfiguration network) {
            this.network = network;
            return this;
        }

        public EncryptionConfiguration build() {
            return new EncryptionConfiguration(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptionConfiguration that = (EncryptionConfiguration) o;
        return Objects.equals(kms, that.kms) &&
                Objects.equals(encryption, that.encryption) &&
                Objects.equals(keyRotation, that.keyRotation) &&
                Objects.equals(caching, that.caching) &&
                Objects.equals(audit, that.audit) &&
                Objects.equals(network, that.network);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kms, encryption, keyRotation, caching, audit, network);
    }

    @Override
    public String toString() {
        return "EncryptionConfiguration{" +
                "kms=" + kms +
                ", encryption=" + encryption +
                ", keyRotation=" + keyRotation +
                ", caching=" + caching +
                ", audit=" + audit +
                ", network=" + network +
                '}';
    }
}
