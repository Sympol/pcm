package dev.vibeafrika.pcm.consent.domain.model;

import dev.vibeafrika.pcm.common.domain.AggregateRoot;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

/**
 * Consent aggregate root.
 * Represents an entry in the immutable consent ledger.
 * Note: Consents are never updated; new entries are appended to the ledger.
 */
@Entity
@Table(name = "consent_ledger", indexes = {
        @Index(name = "idx_consent_profile", columnList = "profile_id, timestamp DESC"),
        @Index(name = "idx_consent_purpose", columnList = "profile_id, purpose, timestamp DESC")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Consent implements AggregateRoot<UUID> {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false, length = 50)
    private String tenantId;

    @Column(name = "profile_id", nullable = false)
    private UUID profileId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private ConsentPurpose purpose;

    @Column(nullable = false)
    private boolean granted;

    @Column(nullable = false, length = 20)
    private String version;

    @Column(name = "consent_text", nullable = false, columnDefinition = "TEXT")
    private String consentText;

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private Instant timestamp;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    @Column(name = "proof_hash", nullable = false, length = 64)
    private String proofHash;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "metadata")
    private String metadata;

    private Consent(String tenantId, UUID profileId, ConsentPurpose purpose, boolean granted,
            String version, String consentText, String ipAddress,
            String userAgent, String proofHash) {
        this.id = UUID.randomUUID();
        this.tenantId = tenantId;
        this.profileId = profileId;
        this.purpose = purpose;
        this.granted = granted;
        this.version = version;
        this.consentText = consentText;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.proofHash = proofHash;
    }

    public static Consent grant(String tenantId, UUID profileId, ConsentPurpose purpose, String version,
            String consentText, String ipAddress, String userAgent,
            String proofHash) {
        return new Consent(tenantId, profileId, purpose, true, version, consentText, ipAddress, userAgent, proofHash);
    }

    public static Consent revoke(String tenantId, UUID profileId, ConsentPurpose purpose, String version,
            String consentText, String ipAddress, String userAgent,
            String proofHash) {
        return new Consent(tenantId, profileId, purpose, false, version, consentText, ipAddress, userAgent, proofHash);
    }
}
