-- Undo migration for V4: Segment context tables
-- Drop segment_tags first to satisfy FK dependency on segment_segments

DROP TABLE IF EXISTS segment_tags;
DROP TABLE IF EXISTS segment_segments;
