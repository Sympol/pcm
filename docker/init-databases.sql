-- PCM — Single database for the modular monolith
-- All bounded contexts share one PostgreSQL database; Flyway manages the schema.

-- The 'pcm' user and 'pcm' database are created by the POSTGRES_USER / POSTGRES_DB
-- environment variables in docker-compose.yml.
-- This script just ensures the schema privileges are correct.

\c pcm;
GRANT ALL ON SCHEMA public TO pcm;
