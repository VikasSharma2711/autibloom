-- AUTIBLOOM Phase 13.2 Authentication & Signup migration
CREATE EXTENSION IF NOT EXISTS pgcrypto;
ALTER TABLE therapists ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'THERAPIST';
ALTER TABLE therapists ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='therapists_role_check') THEN
    ALTER TABLE therapists ADD CONSTRAINT therapists_role_check CHECK(role IN ('ADMIN','THERAPIST'));
  END IF;
END $$;
CREATE TABLE IF NOT EXISTS user_sessions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 therapist_id UUID NOT NULL REFERENCES therapists(id) ON DELETE CASCADE,
 session_hash TEXT NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_hash ON user_sessions(session_hash);
CREATE TABLE IF NOT EXISTS parent_users (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, display_name TEXT NOT NULL,
 is_active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS parent_sessions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), parent_id UUID NOT NULL REFERENCES parent_users(id) ON DELETE CASCADE,
 session_hash TEXT NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_parent_sessions_hash ON parent_sessions(session_hash);
