-- Migration V2: Create Profile Context Tables
-- Table prefix: profile_
-- Description: Creates tables for user profiles with GDPR erasure support

-- Create profile_profiles table
CREATE TABLE profile_profiles (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(100) NOT NULL,
    handle VARCHAR(500) NOT NULL,
    attributes JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version BIGINT NOT NULL DEFAULT 0,
    deleted BOOLEAN NOT NULL DEFAULT FALSE
);

-- Create indexes for profile_profiles
CREATE INDEX idx_profile_tenant ON profile_profiles(tenant_id);
CREATE UNIQUE INDEX idx_profile_handle ON profile_profiles(handle);
CREATE INDEX idx_profile_tenant_id ON profile_profiles(tenant_id, id);
CREATE INDEX idx_profile_deleted ON profile_profiles(deleted) WHERE deleted = FALSE;
CREATE INDEX idx_profile_attributes ON profile_profiles USING GIN (attributes);

-- Add comments for documentation
COMMENT ON TABLE profile_profiles IS 'Stores user profiles with GDPR erasure support';
COMMENT ON COLUMN profile_profiles.id IS 'Unique identifier for the profile';
COMMENT ON COLUMN profile_profiles.tenant_id IS 'Tenant identifier for multi-tenancy';
COMMENT ON COLUMN profile_profiles.handle IS 'Unique user handle (encrypted PII, up to 500 chars)';
COMMENT ON COLUMN profile_profiles.attributes IS 'Dynamic profile attributes stored as JSON';
COMMENT ON COLUMN profile_profiles.deleted IS 'Soft delete flag for GDPR erasure';
COMMENT ON COLUMN profile_profiles.version IS 'Optimistic locking version';
