package dev.vibeafrika.pcm.domain.encryption;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Value object representing a completed incident report for a key compromise event.
 *
 * <p>An incident report captures:
 * <ul>
 *   <li>The incident identifier and timestamp</li>
 *   <li>The compromised key information</li>
 *   <li>The scope of affected data (field identifiers / record IDs)</li>
 *   <li>Actions taken during incident response</li>
 *   <li>The new key ID used for re-encryption (if re-encryption was performed)</li>
 * </ul>
 *
 * <p>The report MUST NOT contain plaintext PII or key material.
 */
public final class IncidentReport {

    private final UUID incidentId;
    private final Instant reportedAt;
    private final CompromisedKeyInfo compromisedKeyInfo;
    private final List<String> affectedDataScope;
    private final List<String> actionsTaken;
    private final UUID newKeyId;
    private final int reEncryptedCount;

    private IncidentReport(Builder builder) {
        this.incidentId = Objects.requireNonNull(builder.incidentId, "Incident ID cannot be null");
        this.reportedAt = Objects.requireNonNull(builder.reportedAt, "Reported-at timestamp cannot be null");
        this.compromisedKeyInfo = Objects.requireNonNull(builder.compromisedKeyInfo,
                "Compromised key info cannot be null");
        this.affectedDataScope = Collections.unmodifiableList(
                Objects.requireNonNull(builder.affectedDataScope, "Affected data scope cannot be null"));
        this.actionsTaken = Collections.unmodifiableList(
                Objects.requireNonNull(builder.actionsTaken, "Actions taken cannot be null"));
        this.newKeyId = builder.newKeyId;
        this.reEncryptedCount = builder.reEncryptedCount;
    }

    public static Builder builder() {
        return new Builder();
    }

    public UUID getIncidentId() {
        return incidentId;
    }

    public Instant getReportedAt() {
        return reportedAt;
    }

    public CompromisedKeyInfo getCompromisedKeyInfo() {
        return compromisedKeyInfo;
    }

    /** Returns the list of field identifiers / record IDs affected by the compromise. */
    public List<String> getAffectedDataScope() {
        return affectedDataScope;
    }

    /** Returns the list of actions taken during incident response. */
    public List<String> getActionsTaken() {
        return actionsTaken;
    }

    /** Returns the new key ID used for re-encryption, or null if re-encryption was not performed. */
    public UUID getNewKeyId() {
        return newKeyId;
    }

    /** Returns the number of records re-encrypted with the new key. */
    public int getReEncryptedCount() {
        return reEncryptedCount;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IncidentReport that = (IncidentReport) o;
        return Objects.equals(incidentId, that.incidentId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(incidentId);
    }

    @Override
    public String toString() {
        return "IncidentReport{incidentId=" + incidentId +
                ", reportedAt=" + reportedAt +
                ", compromisedKeyId=" + compromisedKeyInfo.getKeyId() +
                ", affectedCount=" + affectedDataScope.size() +
                ", reEncryptedCount=" + reEncryptedCount + "}";
    }

    public static final class Builder {
        private UUID incidentId;
        private Instant reportedAt;
        private CompromisedKeyInfo compromisedKeyInfo;
        private List<String> affectedDataScope = Collections.emptyList();
        private List<String> actionsTaken = Collections.emptyList();
        private UUID newKeyId;
        private int reEncryptedCount;

        private Builder() {
        }

        public Builder incidentId(UUID incidentId) {
            this.incidentId = incidentId;
            return this;
        }

        public Builder reportedAt(Instant reportedAt) {
            this.reportedAt = reportedAt;
            return this;
        }

        public Builder compromisedKeyInfo(CompromisedKeyInfo compromisedKeyInfo) {
            this.compromisedKeyInfo = compromisedKeyInfo;
            return this;
        }

        public Builder affectedDataScope(List<String> affectedDataScope) {
            this.affectedDataScope = affectedDataScope;
            return this;
        }

        public Builder actionsTaken(List<String> actionsTaken) {
            this.actionsTaken = actionsTaken;
            return this;
        }

        public Builder newKeyId(UUID newKeyId) {
            this.newKeyId = newKeyId;
            return this;
        }

        public Builder reEncryptedCount(int reEncryptedCount) {
            this.reEncryptedCount = reEncryptedCount;
            return this;
        }

        public IncidentReport build() {
            return new IncidentReport(this);
        }
    }
}
