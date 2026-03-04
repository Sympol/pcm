package dev.vibeafrika.pcm.consent.infrastructure.persistence.entity;

import dev.vibeafrika.pcm.consent.domain.model.ConsentStatus;
import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * JPA persistence entity for Consent.
 * Uses table prefix "consent_" for modular monolith isolation.
 * Implements immutable ledger pattern with consent events.
 */
@Entity
@Table(name = "consent_consents", indexes = {
    @Index(name = "idx_consent_profile", columnList = "profile_id"),
    @Index(name = "idx_consent_tenant", columnList = "tenant_id"),
    @Index(name = "idx_consent_purpose", columnList = "purpose"),
    @Index(name = "idx_consent_status", columnList = "status"),
    @Index(name = "idx_consent_tenant_profile", columnList = "tenant_id,profile_id")
})
@EntityListeners(AuditingEntityListener.class)
public class ConsentJpaEntity {

    @Id
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "profile_id", nullable = false)
    private UUID profileId;

    @Column(name = "tenant_id", nullable = false, length = 100)
    private String tenantId;

    @Column(name = "purpose", nullable = false, length = 100)
    private String purpose;

    @Column(name = "scope", nullable = false, length = 100)
    private String scope;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private ConsentStatus status;

    @OneToMany(mappedBy = "consent", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @OrderBy("timestamp ASC")
    private List<ConsentEventJpaEntity> events = new ArrayList<>();

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    @Column(name = "version")
    private Long version;

    // Default constructor for JPA
    public ConsentJpaEntity() {
    }

    // Getters and setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public UUID getProfileId() {
        return profileId;
    }

    public void setProfileId(UUID profileId) {
        this.profileId = profileId;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getPurpose() {
        return purpose;
    }

    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public ConsentStatus getStatus() {
        return status;
    }

    public void setStatus(ConsentStatus status) {
        this.status = status;
    }

    public List<ConsentEventJpaEntity> getEvents() {
        return events;
    }

    public void setEvents(List<ConsentEventJpaEntity> events) {
        this.events = events;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Long getVersion() {
        return version;
    }

    public void setVersion(Long version) {
        this.version = version;
    }
}
