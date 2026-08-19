-- AUTIBLOOM Phase 13.3 Email Verification + Password Reset
ALTER TABLE therapists ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;
ALTER TABLE parent_users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;
-- Existing accounts created before email verification was introduced remain usable.
UPDATE therapists SET email_verified_at = COALESCE(email_verified_at, created_at) WHERE email_verified_at IS NULL;
UPDATE parent_users SET email_verified_at = COALESCE(email_verified_at, created_at) WHERE email_verified_at IS NULL;

CREATE TABLE IF NOT EXISTS email_verification_tokens(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 account_type TEXT NOT NULL CHECK(account_type IN ('THERAPIST','PARENT')),
 account_id UUID NOT NULL,
 token_hash TEXT NOT NULL UNIQUE,
 expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_account ON email_verification_tokens(account_type, account_id, expires_at);

CREATE TABLE IF NOT EXISTS password_reset_tokens(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 account_type TEXT NOT NULL CHECK(account_type IN ('THERAPIST','PARENT')),
 account_id UUID NOT NULL,
 token_hash TEXT NOT NULL UNIQUE,
 expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_account ON password_reset_tokens(account_type, account_id, expires_at);
