-- Migration V1: Create Preference Context Tables
-- Table prefix: preference_
-- Description: Creates tables for user UX preferences and settings

-- Create preference_preferences table
CREATE TABLE preference_preferences (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(100) NOT NULL,
    profile_id UUID NOT NULL,
    last_updated TIMESTAMP NOT NULL,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uk_preference_profile UNIQUE (profile_id)
);

-- Create indexes for preference_preferences
CREATE INDEX idx_preference_tenant ON preference_preferences(tenant_id);
CREATE INDEX idx_preference_profile ON preference_preferences(profile_id);
CREATE INDEX idx_preference_tenant_profile ON preference_preferences(tenant_id, profile_id);
CREATE INDEX idx_preference_deleted ON preference_preferences(deleted) WHERE deleted = FALSE;

-- Create preference_settings table (for @ElementCollection)
CREATE TABLE preference_settings (
    preference_id UUID NOT NULL,
    setting_key VARCHAR(100) NOT NULL,
    setting_value VARCHAR(1000),
    PRIMARY KEY (preference_id, setting_key),
    CONSTRAINT fk_preference_settings_preference 
        FOREIGN KEY (preference_id) 
        REFERENCES preference_preferences(id) 
        ON DELETE CASCADE
);

-- Create index for preference_settings
CREATE INDEX idx_preference_settings_key ON preference_settings(setting_key);

-- Add comments for documentation
COMMENT ON TABLE preference_preferences IS 'Stores user UX preferences and settings';
COMMENT ON COLUMN preference_preferences.id IS 'Unique identifier for the preference';
COMMENT ON COLUMN preference_preferences.tenant_id IS 'Tenant identifier for multi-tenancy';
COMMENT ON COLUMN preference_preferences.profile_id IS 'Associated profile identifier';
COMMENT ON COLUMN preference_preferences.last_updated IS 'Timestamp of last preference update';
COMMENT ON COLUMN preference_preferences.deleted IS 'Soft delete flag';
COMMENT ON COLUMN preference_preferences.version IS 'Optimistic locking version';

COMMENT ON TABLE preference_settings IS 'Stores individual preference settings as key-value pairs';
COMMENT ON COLUMN preference_settings.preference_id IS 'Reference to parent preference';
COMMENT ON COLUMN preference_settings.setting_key IS 'Setting key (e.g., theme, language)';
COMMENT ON COLUMN preference_settings.setting_value IS 'Setting value';
