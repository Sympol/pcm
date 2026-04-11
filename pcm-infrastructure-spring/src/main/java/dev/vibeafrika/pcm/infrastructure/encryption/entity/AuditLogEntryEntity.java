package dev.vibeafrika.pcm.infrastructure.encryption.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * JPA entity for persisting encrypted and signed audit log entries.
 *
 * <p>This entity is intentionally append-only: there are no setters for any
 * field after construction, and the associated repository exposes no delete
 * or update operations. The combination of immutable fields and a restricted
 * repository interface enforces the append-only property.
 *
 * <p>The {@code encryptedPayload} column stores the AES-256-GCM ciphertext of
 * the structured log entry. The {@code hmacSignature} column stores the
 * HMAC-SHA256 hex digest computed over the plaintext payload before encryption,
 * allowing integrity verification without decryption.
 */
@Entity
@Table(name = "encryption_audit_log",
        indexes = {
                @Index(name = "idx_audit_log_event_type", columnList = "event_type"),
                @Index(name = "idx_audit_log_created_at", columnList = "created_at")
        })
public class AuditLogEntryEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "audit_log_seq")
    @SequenceGenerator(name = "audit_log_seq", sequenceName = "encryption_audit_log_seq",
            allocationSize = 50)
    private Long id;

    /**
     * Monotonically increasing sequence number within this JVM instance.
     * Stored alongside the DB-generated ID to detect gaps that could indicate
     * tampering with the log sequence.
     */
    @Column(name = "sequence_number", nullable = false)
    private long sequenceNumber;

    /**
     * Short event type label (e.g. "ENCRYPTION", "KEY_ROTATION") stored in
     * plaintext to allow efficient filtering without decryption.
     */
    @Column(name = "event_type", nullable = false, length = 64)
    private String eventType;

    /**
     * Wall-clock timestamp of the original event (not the persistence time).
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * AES-256-GCM ciphertext of the full structured log entry JSON.
     * Stored in the standard ciphertext format: [ver|alg|key_id|IV|ct|tag].
     */
    @Column(name = "encrypted_payload", nullable = false, columnDefinition = "BYTEA")
    private byte[] encryptedPayload;

    /**
     * HMAC-SHA256 hex digest computed over the plaintext payload before
     * encryption. Allows integrity verification independent of decryption.
     */
    @Column(name = "hmac_signature", nullable = false, length = 64)
    private String hmacSignature;

    protected AuditLogEntryEntity() {
        // JPA requires a no-arg constructor
    }

    public AuditLogEntryEntity(long sequenceNumber,
                               String eventType,
                               Instant createdAt,
                               byte[] encryptedPayload,
                               String hmacSignature) {
        this.sequenceNumber = sequenceNumber;
        this.eventType = eventType;
        this.createdAt = createdAt;
        this.encryptedPayload = encryptedPayload.clone();
        this.hmacSignature = hmacSignature;
    }

    // Read-only accessors – no setters to enforce immutability after construction

    public Long getId() {
        return id;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public String getEventType() {
        return eventType;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public byte[] getEncryptedPayload() {
        return encryptedPayload.clone();
    }

    public String getHmacSignature() {
        return hmacSignature;
    }
}
