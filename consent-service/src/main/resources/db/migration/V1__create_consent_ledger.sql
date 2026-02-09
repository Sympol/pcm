CREATE TABLE consent_ledger (
    id UUID PRIMARY KEY,
    profile_id UUID NOT NULL,
    tenant_id VARCHAR(100) NOT NULL,
    purpose VARCHAR(50) NOT NULL,
    granted BOOLEAN NOT NULL,
    version VARCHAR(20) NOT NULL,
    consent_text TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    proof_hash VARCHAR(64) NOT NULL,
    metadata JSON
);

CREATE INDEX idx_consent_profile ON consent_ledger(profile_id, timestamp DESC);
CREATE INDEX idx_consent_purpose ON consent_ledger(purpose, profile_id, timestamp DESC);
