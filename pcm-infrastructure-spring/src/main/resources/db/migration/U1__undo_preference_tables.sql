-- Undo migration for V1: Preference context tables
-- Drop preference_settings first to satisfy FK dependency on preference_preferences

DROP TABLE IF EXISTS preference_settings;
DROP TABLE IF EXISTS preference_preferences;
