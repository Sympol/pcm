-- Migration V4: Create Segment Context Tables
-- Table prefix: segment_
-- Description: Creates tables for profile segmentation data (tags and scores)

-- Create segment_segments table (stores tags and scores per profile)
CREATE TABLE segment_segments (
    id UUID PRIMARY KEY,
    tenant_id VARCHAR(100) NOT NULL,
    profile_id UUID NOT NULL,
    scores JSONB NOT NULL DEFAULT '{}',
    last_updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_segment_tenant_profile UNIQUE (tenant_id, profile_id)
);

-- Create segment_tags table (stores tags for each segment)
-- Uses composite PK (segment_id, tag) to match Hibernate's @ElementCollection Set mapping
CREATE TABLE segment_tags (
    segment_id UUID NOT NULL,
    tag VARCHAR(100) NOT NULL,
    PRIMARY KEY (segment_id, tag),
    CONSTRAINT fk_segment_tags_segment 
        FOREIGN KEY (segment_id) 
        REFERENCES segment_segments(id) 
        ON DELETE CASCADE
);

-- Create indexes for segment_segments
CREATE INDEX idx_segment_tenant ON segment_segments(tenant_id);
CREATE INDEX idx_segment_profile ON segment_segments(profile_id);
CREATE INDEX idx_segment_tenant_profile ON segment_segments(tenant_id, profile_id);
CREATE INDEX idx_segment_scores ON segment_segments USING GIN (scores);

-- Create indexes for segment_tags
CREATE INDEX idx_segment_tags_segment ON segment_tags(segment_id);
CREATE INDEX idx_segment_tags_tag ON segment_tags(tag);

-- Add comments for documentation
COMMENT ON TABLE segment_segments IS 'Stores segmentation data (tags and scores) per profile';
COMMENT ON COLUMN segment_segments.id IS 'Unique identifier for the segment';
COMMENT ON COLUMN segment_segments.tenant_id IS 'Tenant identifier for multi-tenancy';
COMMENT ON COLUMN segment_segments.profile_id IS 'Profile this segment data belongs to';
COMMENT ON COLUMN segment_segments.scores IS 'Behavioral scores stored as JSON (key-value pairs)';
COMMENT ON COLUMN segment_segments.last_updated IS 'Last time segment data was updated';

COMMENT ON TABLE segment_tags IS 'Stores tags associated with each segment';
COMMENT ON COLUMN segment_tags.segment_id IS 'Reference to segment';
COMMENT ON COLUMN segment_tags.tag IS 'Tag value';
