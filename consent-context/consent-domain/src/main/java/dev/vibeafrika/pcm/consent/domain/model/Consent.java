package dev.vibeafrika.pcm.consent.domain.model;

import dev.vibeafrika.pcm.consent.domain.exception.ConsentRevokedException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Consent aggregate root - pure domain model with immutable ledger pattern.
 * No framework annotations, no persistence concerns.
 * Consents are append-only - revocation creates a new event rather than modifying existing data.
 */
public final class Consent {
    private final ConsentId id;
    private final ProfileId profileId;
    private final TenantId tenantId;
    private final ConsentPurpose purpose;
    private final ConsentScope scope;
    private final List<ConsentEvent> events;
    private ConsentStatus status;
    private Instant createdAt;
    private Instant updatedAt;
    private Long version;

    // Private constructor - use factory methods
    private Consent(ConsentId id, ProfileId profileId, TenantId tenantId,
                    ConsentPurpose purpose, ConsentScope scope) {
        this.id = requireNonNull(id, "Consent ID cannot be null");
        this.profileId = requireNonNull(profileId, "Profile ID cannot be null");
        this.tenantId = requireNonNull(tenantId, "Tenant ID cannot be null");
        this.purpose = requireNonNull(purpose, "Consent purpose cannot be null");
        this.scope = requireNonNull(scope, "Consent scope cannot be null");
        this.events = new ArrayList<>();
        this.status = ConsentStatus.GRANTED;
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
        this.version = 0L;
        
        // Add initial grant event
        this.events.add(new ConsentEvent(ConsentStatus.GRANTED, Instant.now()));
    }

    /**
     * Factory method to create a new Consent (grant).
     */
    public static Consent create(ProfileId profileId, TenantId tenantId,
                                  ConsentPurpose purpose, ConsentScope scope) {
        return new Consent(ConsentId.generate(), profileId, tenantId, purpose, scope);
    }

    /**
     * Reconstitute a Consent from persistence.
     * Public to allow infrastructure layer mappers to rebuild domain entities.
     */
    public static Consent reconstitute(ConsentId id, ProfileId profileId, TenantId tenantId,
                                ConsentPurpose purpose, ConsentScope scope,
                                ConsentStatus status, List<ConsentEvent> events,
                                Instant createdAt, Instant updatedAt, Long version) {
        Consent consent = new Consent(id, profileId, tenantId, purpose, scope);
        consent.status = status;
        consent.events.clear();
        consent.events.addAll(events);
        consent.createdAt = createdAt;
        consent.updatedAt = updatedAt;
        consent.version = version;
        return consent;
    }

    /**
     * Grant consent (for reconstitution or re-granting after revocation).
     */
    public void grant() {
        this.status = ConsentStatus.GRANTED;
        this.events.add(new ConsentEvent(ConsentStatus.GRANTED, Instant.now()));
        this.updatedAt = Instant.now();
    }

    /**
     * Revoke consent - adds revocation event to immutable ledger.
     */
    public void revoke() {
        if (this.status == ConsentStatus.REVOKED) {
            throw new ConsentRevokedException("Consent already revoked: " + id);
        }
        this.status = ConsentStatus.REVOKED;
        this.events.add(new ConsentEvent(ConsentStatus.REVOKED, Instant.now()));
        this.updatedAt = Instant.now();
    }

    /**
     * Verify if consent is currently active.
     */
    public boolean verify() {
        return this.status == ConsentStatus.GRANTED;
    }

    /**
     * Check if consent is active.
     */
    public boolean isActive() {
        return this.status == ConsentStatus.GRANTED;
    }

    /**
     * Get consent history (immutable ledger).
     */
    public List<ConsentEvent> getHistory() {
        return Collections.unmodifiableList(events);
    }

    // Getters
    public ConsentId getId() { return id; }
    public ProfileId getProfileId() { return profileId; }
    public TenantId getTenantId() { return tenantId; }
    public ConsentPurpose getPurpose() { return purpose; }
    public ConsentScope getScope() { return scope; }
    public ConsentStatus getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public Long getVersion() { return version; }

    private static <T> T requireNonNull(T obj, String message) {
        if (obj == null) {
            throw new IllegalArgumentException(message);
        }
        return obj;
    }

    /**
     * ConsentEvent - represents an event in the consent ledger.
     * Immutable record of consent state changes.
     */
    public static class ConsentEvent {
        private final ConsentStatus status;
        private final Instant timestamp;

        public ConsentEvent(ConsentStatus status, Instant timestamp) {
            this.status = status;
            this.timestamp = timestamp;
        }

        public ConsentStatus getStatus() { return status; }
        public Instant getTimestamp() { return timestamp; }
    }
}
