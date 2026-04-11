package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Value object representing a single backup record.
 *
 * <p>A backup record contains ONLY ciphertext — never plaintext PII.
 * This ensures that database backups do not expose sensitive data even if
 * the backup storage is compromised.
 */
public final class BackupRecord {

    private final UUID recordId;
    private final Ciphertext ciphertext;
    private final UUID dekId;
    private final BoundedContext context;
    private final String fieldIdentifier;
    private final Instant backedUpAt;

    private BackupRecord(UUID recordId, Ciphertext ciphertext, UUID dekId,
                         BoundedContext context, String fieldIdentifier, Instant backedUpAt) {
        this.recordId = Objects.requireNonNull(recordId, "Record ID cannot be null");
        this.ciphertext = Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
        this.dekId = Objects.requireNonNull(dekId, "DEK ID cannot be null");
        this.context = Objects.requireNonNull(context, "Context cannot be null");
        this.fieldIdentifier = Objects.requireNonNull(fieldIdentifier, "Field identifier cannot be null");
        this.backedUpAt = Objects.requireNonNull(backedUpAt, "Backup timestamp cannot be null");
    }

    /**
     * Creates a backup record containing only ciphertext (no plaintext PII).
     *
     * @param recordId        unique identifier for this backup record
     * @param ciphertext      the encrypted data (never plaintext)
     * @param dekId           the DEK used to encrypt this ciphertext
     * @param context         the bounded context this record belongs to
     * @param fieldIdentifier the field name (e.g. "email", "phone") — not the value
     * @param backedUpAt      when this record was backed up
     * @return a new BackupRecord
     */
    public static BackupRecord of(UUID recordId, Ciphertext ciphertext, UUID dekId,
                                  BoundedContext context, String fieldIdentifier, Instant backedUpAt) {
        return new BackupRecord(recordId, ciphertext, dekId, context, fieldIdentifier, backedUpAt);
    }

    public UUID getRecordId() {
        return recordId;
    }

    /** Returns the encrypted ciphertext. This is NEVER plaintext PII. */
    public Ciphertext getCiphertext() {
        return ciphertext;
    }

    public UUID getDekId() {
        return dekId;
    }

    public BoundedContext getContext() {
        return context;
    }

    /** Returns the field name identifier (e.g. "email") — never the plaintext value. */
    public String getFieldIdentifier() {
        return fieldIdentifier;
    }

    public Instant getBackedUpAt() {
        return backedUpAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BackupRecord that = (BackupRecord) o;
        return Objects.equals(recordId, that.recordId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(recordId);
    }

    @Override
    public String toString() {
        return "BackupRecord{recordId=" + recordId +
                ", dekId=" + dekId +
                ", context=" + context +
                ", fieldIdentifier=" + fieldIdentifier +
                ", backedUpAt=" + backedUpAt + "}";
    }
}
