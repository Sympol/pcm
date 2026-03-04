-- Migration V3: Create Consent Context Tables
-- Table prefix: consent_
-- Description: Creates tables for consent management with immutable ledger pattern

-- Create consent_consents table
CREATE TABLE consent_consents (
    id UUID PRIMARY KEY,
    profile_id UUID NOT NULL,
    tenant_id VARCHAR(100) NOT NULL,
    purpose VARCHAR(100) NOT NULL,
    scope VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT chk_consent_status CHECK (status IN ('GRANTED', 'REVOKED', 'EXPIRED'))
);

-- Create indexes for consent_consents
CREATE INDEX idx_consent_profile ON consent_consents(profile_id);
CREATE INDEX idx_consent_tenant ON consent_consents(tenant_id);
CREATE INDEX idx_consent_purpose ON consent_consents(purpose);
CREATE INDEX idx_consent_status ON consent_consents(status);
CREATE INDEX idx_consent_tenant_profile ON consent_consents(tenant_id, profile_id);
CREATE INDEX idx_consent_active ON consent_consents(profile_id, status) WHERE status = 'GRANTED';

-- Create consent_events table (immutable ledger)
CREATE TABLE consent_events (
    id BIGSERIAL PRIMARY KEY,
    consent_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    CONSTRAINT fk_consent_events_consent 
        FOREIGN KEY (consent_id) 
        REFERENCES consent_consents(id) 
        ON DELETE CASCADE,
    CONSTRAINT chk_event_status CHECK (status IN ('GRANTED', 'REVOKED', 'EXPIRED'))
);

-- Create indexes for consent_events
CREATE INDEX idx_consent_events_consent ON consent_events(consent_id);
CREATE INDEX idx_consent_events_timestamp ON consent_events(timestamp);

-- Add comments for documentation
COMMENT ON TABLE consent_consents IS 'Stores user consents with immutable ledger pattern';
COMMENT ON COLUMN consent_consents.id IS 'Unique identifier for the consent';
COMMENT ON COLUMN consent_consents.profile_id IS 'Associated profile identifier';
COMMENT ON COLUMN consent_consents.tenant_id IS 'Tenant identifier for multi-tenancy';
COMMENT ON COLUMN consent_consents.purpose IS 'Consent purpose (e.g., marketing, analytics)';
COMMENT ON COLUMN consent_consents.scope IS 'Consent scope (e.g., email, tracking)';
COMMENT ON COLUMN consent_consents.status IS 'Current consent status';
COMMENT ON COLUMN consent_consents.version IS 'Optimistic locking version';

COMMENT ON TABLE consent_events IS 'Immutable ledger of consent state changes';
COMMENT ON COLUMN consent_events.consent_id IS 'Reference to parent consent';
COMMENT ON COLUMN consent_events.status IS 'Status at this event';
COMMENT ON COLUMN consent_events.timestamp IS 'When this event occurred';
