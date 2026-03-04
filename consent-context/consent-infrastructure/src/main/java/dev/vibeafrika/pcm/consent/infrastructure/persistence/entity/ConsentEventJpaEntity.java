package dev.vibeafrika.pcm.consent.infrastructure.persistence.entity;

import dev.vibeafrika.pcm.consent.domain.model.ConsentStatus;
import jakarta.persistence.*;

import java.time.Instant;

/**
 * JPA entity for consent events (immutable ledger).
 */
@Entity
@Table(name = "consent_events", indexes = {
    @Index(name = "idx_consent_events_consent", columnList = "consent_id"),
    @Index(name = "idx_consent_events_timestamp", columnList = "timestamp")
})
public class ConsentEventJpaEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "consent_id", nullable = false)
    private ConsentJpaEntity consent;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private ConsentStatus status;

    @Column(name = "timestamp", nullable = false)
    private Instant timestamp;

    // Default constructor for JPA
    public ConsentEventJpaEntity() {
    }

    public ConsentEventJpaEntity(ConsentStatus status, Instant timestamp) {
        this.status = status;
        this.timestamp = timestamp;
    }

    // Getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public ConsentJpaEntity getConsent() {
        return consent;
    }

    public void setConsent(ConsentJpaEntity consent) {
        this.consent = consent;
    }

    public ConsentStatus getStatus() {
        return status;
    }

    public void setStatus(ConsentStatus status) {
        this.status = status;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }
}
