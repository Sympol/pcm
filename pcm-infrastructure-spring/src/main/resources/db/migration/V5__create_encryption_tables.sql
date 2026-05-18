-- V5: Create encryption infrastructure tables
-- Audit logs encrypted at rest
-- Append-only audit log storage
-- Audit log entries signed for integrity

-- IV counter state table (supports DatabaseIVCounterStorage)
CREATE SEQUENCE IF NOT EXISTS encryption_iv_counter_state_seq
    START WITH 1
    INCREMENT BY 50
    NO CYCLE;

CREATE TABLE IF NOT EXISTS encryption_iv_counter_state (
    id              BIGINT      NOT NULL DEFAULT nextval('encryption_iv_counter_state_seq') PRIMARY KEY,
    dek_id          UUID        NOT NULL UNIQUE,
    random_base     BIGINT      NOT NULL,
    counter         INTEGER     NOT NULL,
    last_persisted  INTEGER     NOT NULL,
    version         BIGINT      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_iv_counter_dek_id ON encryption_iv_counter_state (dek_id);

-- Audit log table (append-only; no UPDATE or DELETE permissions granted)
-- encrypted_payload: AES-256-GCM ciphertext of the full structured log entry
-- hmac_signature:    HMAC-SHA256 hex digest over the plaintext payload
CREATE TABLE IF NOT EXISTS encryption_audit_log (
    id               BIGSERIAL    PRIMARY KEY,
    sequence_number  BIGINT       NOT NULL,
    event_type       VARCHAR(64)  NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL,
    encrypted_payload BYTEA       NOT NULL,
    hmac_signature   VARCHAR(64)  NOT NULL
);

CREATE SEQUENCE IF NOT EXISTS encryption_audit_log_seq
    START WITH 1
    INCREMENT BY 50
    NO CYCLE;

CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON encryption_audit_log (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at  ON encryption_audit_log (created_at);

-- Revoke UPDATE and DELETE on the audit log table to enforce append-only at DB level
-- (application-level enforcement is also in place via AuditLogEntryRepository)
REVOKE UPDATE, DELETE ON encryption_audit_log FROM PUBLIC;
