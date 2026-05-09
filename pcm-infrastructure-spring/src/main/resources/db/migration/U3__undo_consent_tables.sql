-- Undo migration for V3: Consent context tables
-- Drop consent_events first to satisfy FK dependency on consent_consents

DROP TABLE IF EXISTS consent_events;
DROP TABLE IF EXISTS consent_consents;
