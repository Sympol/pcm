-- Create profiles table
CREATE TABLE profiles (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(100) NOT NULL,
    handle VARCHAR(50) NOT NULL UNIQUE,
    attributes JSON,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    version BIGINT NOT NULL DEFAULT 0,
    deleted_at TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_profile_tenant ON profiles(tenant_id);
CREATE INDEX idx_profile_handle ON profiles(handle);
CREATE INDEX idx_profile_created_at ON profiles(created_at DESC);
CREATE INDEX idx_profile_deleted_at ON profiles(deleted_at);

-- Add comments
COMMENT ON TABLE profiles IS 'User profiles with dynamic attributes stored as JSONB';
COMMENT ON COLUMN profiles.id IS 'Unique profile identifier (UUID)';
COMMENT ON COLUMN profiles.tenant_id IS 'Tenant identifier for multi-tenancy';
COMMENT ON COLUMN profiles.handle IS 'Unique user handle (e.g., username)';
COMMENT ON COLUMN profiles.attributes IS 'Dynamic profile attributes stored as JSON';
COMMENT ON COLUMN profiles.deleted_at IS 'Soft delete flag for GDPR compliance';
