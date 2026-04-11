-- Migration V6: Add blind index columns for searchable encryption
-- Adds blind index columns to support HMAC-SHA256 blind indexing on encrypted PII fields.
-- Also widens encrypted PII columns to accommodate ciphertext (46 bytes overhead + base64).

-- profile_profiles: add handle_blind_index, widen handle for ciphertext
ALTER TABLE profile_profiles
    ADD COLUMN IF NOT EXISTS handle_blind_index VARCHAR(64);

ALTER TABLE profile_profiles
    ALTER COLUMN handle TYPE VARCHAR(500);

CREATE INDEX IF NOT EXISTS idx_profile_handle_blind_index ON profile_profiles(handle_blind_index);

COMMENT ON COLUMN profile_profiles.handle_blind_index IS 'HMAC-SHA256 blind index for searching encrypted handle';
