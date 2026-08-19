-- AUTIBLOOM Phase 13.5: mandatory MFA for ADMIN/THERAPIST accounts.
-- Run after schema.sql on an existing installation.
CREATE TABLE IF NOT EXISTS mfa_methods (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  therapist_id UUID NOT NULL UNIQUE REFERENCES therapists(id) ON DELETE CASCADE,
  secret_encrypted TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  enabled_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS mfa_challenges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  therapist_id UUID NOT NULL REFERENCES therapists(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL CHECK(type IN ('SETUP','LOGIN')),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_token ON mfa_challenges(token_hash);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_therapist_type ON mfa_challenges(therapist_id,type,created_at DESC);
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  therapist_id UUID NOT NULL REFERENCES therapists(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_therapist ON mfa_recovery_codes(therapist_id,used_at);
