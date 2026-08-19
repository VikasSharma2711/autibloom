-- Only declare pgcrypto once.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE therapists(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'THERAPIST' CHECK(role IN ('ADMIN','THERAPIST')), is_active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE children(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), therapist_id UUID NOT NULL REFERENCES therapists(id),
 name TEXT NOT NULL, date_of_birth DATE, caregiver_name TEXT, primary_concern TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE assessments(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), child_id UUID NOT NULL REFERENCES children(id),
 instrument_version TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN('Draft','In Progress','Completed')),
 started_at TIMESTAMPTZ NOT NULL DEFAULT now(), completed_at TIMESTAMPTZ,
 therapist_id UUID NOT NULL REFERENCES therapists(id)
);
CREATE TABLE responses(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
 question_id TEXT NOT NULL, response_value SMALLINT, UNIQUE(assessment_id,question_id)
);
CREATE TABLE assessment_scores(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
 score_type TEXT NOT NULL, label TEXT NOT NULL, score NUMERIC(7,2),
 UNIQUE(assessment_id,score_type,label),
 CHECK(score IS NULL OR (score >= 0 AND score <= 100))
);
CREATE TABLE audit_log(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), therapist_id UUID, action TEXT NOT NULL,
 entity_type TEXT, entity_id UUID, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_children_therapist ON children(therapist_id);
CREATE INDEX idx_assessments_child ON assessments(child_id);
CREATE INDEX idx_responses_assessment ON responses(assessment_id);

CREATE INDEX idx_audit_therapist_created ON audit_log(therapist_id,created_at DESC);
CREATE INDEX idx_scores_assessment ON assessment_scores(assessment_id);

-- pgcrypto already declared at top of file; removed duplicate.
CREATE TABLE IF NOT EXISTS user_sessions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 therapist_id UUID NOT NULL REFERENCES therapists(id) ON DELETE CASCADE,
 session_hash TEXT NOT NULL UNIQUE,
 expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_hash ON user_sessions(session_hash);
CREATE TABLE IF NOT EXISTS parent_users (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 display_name TEXT NOT NULL,
 is_active BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS parent_child_links (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 parent_id UUID NOT NULL REFERENCES parent_users(id) ON DELETE CASCADE,
 child_id UUID NOT NULL REFERENCES children(id) ON DELETE CASCADE,
 relationship TEXT NOT NULL,
 verified_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(parent_id,child_id)
);
CREATE INDEX IF NOT EXISTS idx_parent_child_parent ON parent_child_links(parent_id);
CREATE INDEX IF NOT EXISTS idx_parent_child_child ON parent_child_links(child_id);

CREATE TABLE IF NOT EXISTS clinical_reports (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(), assessment_id UUID NOT NULL UNIQUE REFERENCES assessments(id) ON DELETE CASCADE,
therapist_id UUID NOT NULL REFERENCES therapists(id) ON DELETE RESTRICT, report_version TEXT NOT NULL,
-- 'In Review' and 'Approved' are used by the Phase 10 therapist review workflow.
status TEXT NOT NULL DEFAULT 'Draft' CHECK(status IN ('Draft','In Review','Approved','Reviewed','Released')),
clinical_summary JSONB NOT NULL DEFAULT '{}'::jsonb,parent_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,home_program JSONB NOT NULL DEFAULT '[]'::jsonb,
clinician_notes TEXT NOT NULL DEFAULT '',created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
reviewed_at TIMESTAMPTZ,released_at TIMESTAMPTZ);
CREATE INDEX IF NOT EXISTS idx_clinical_reports_therapist ON clinical_reports(therapist_id,updated_at DESC);
-- Phase 13 compatibility: older Phase 8 installations only allowed Draft/Reviewed/Released.
DO $$ BEGIN
  ALTER TABLE clinical_reports DROP CONSTRAINT IF EXISTS clinical_reports_status_check;
  ALTER TABLE clinical_reports ADD CONSTRAINT clinical_reports_status_check CHECK(status IN ('Draft','In Review','Approved','Reviewed','Released'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE TABLE IF NOT EXISTS report_access_log (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),report_id UUID NOT NULL REFERENCES clinical_reports(id) ON DELETE CASCADE,
actor_type TEXT NOT NULL CHECK(actor_type IN ('therapist','parent','system')),actor_id UUID,action TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS idx_report_access_log_report ON report_access_log(report_id,created_at DESC);

-- PHASE 9
CREATE TABLE IF NOT EXISTS parent_sessions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), parent_id UUID NOT NULL REFERENCES parent_users(id) ON DELETE CASCADE,
 session_hash TEXT NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_parent_sessions_hash ON parent_sessions(session_hash);
CREATE TABLE IF NOT EXISTS report_delivery_tokens (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), report_id UUID NOT NULL REFERENCES clinical_reports(id) ON DELETE CASCADE,
 parent_id UUID NOT NULL REFERENCES parent_users(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE,
 expires_at TIMESTAMPTZ NOT NULL, first_viewed_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_report_delivery_report ON report_delivery_tokens(report_id);
CREATE INDEX IF NOT EXISTS idx_report_delivery_parent ON report_delivery_tokens(parent_id);
CREATE TABLE IF NOT EXISTS report_download_log (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), report_id UUID NOT NULL REFERENCES clinical_reports(id) ON DELETE CASCADE,
 parent_id UUID REFERENCES parent_users(id) ON DELETE SET NULL, actor_type TEXT NOT NULL CHECK(actor_type IN ('therapist','parent')),
 action TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- AUTIBLOOM PHASE 10: Therapist Clinical Review & Release
CREATE TABLE IF NOT EXISTS clinical_report_reviews (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 report_id UUID NOT NULL REFERENCES clinical_reports(id) ON DELETE CASCADE,
 therapist_id UUID NOT NULL REFERENCES therapists(id) ON DELETE RESTRICT,
 action TEXT NOT NULL CHECK(action IN ('DRAFT_SAVED','SUBMITTED_FOR_REVIEW','APPROVED','RETURNED','RELEASED')),
 note TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_clinical_report_reviews_report ON clinical_report_reviews(report_id);
CREATE TABLE IF NOT EXISTS clinical_report_release_log (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 report_id UUID NOT NULL REFERENCES clinical_reports(id) ON DELETE CASCADE,
 therapist_id UUID NOT NULL REFERENCES therapists(id) ON DELETE RESTRICT,
 release_channel TEXT NOT NULL CHECK(release_channel IN ('PARENT_PORTAL','INTERNAL')),
 released_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_release_log_report ON clinical_report_release_log(report_id);

-- AUTIBLOOM PHASE 12
CREATE TABLE IF NOT EXISTS admin_audit_log (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),actor_user_id UUID NOT NULL,actor_role TEXT NOT NULL,action TEXT NOT NULL,resource_type TEXT NOT NULL,resource_id UUID,metadata JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_log(created_at DESC);
CREATE TABLE IF NOT EXISTS app_roles (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),role_key TEXT UNIQUE NOT NULL,display_name TEXT NOT NULL,permissions JSONB NOT NULL DEFAULT '[]'::jsonb,created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS operational_events (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),event_type TEXT NOT NULL,severity TEXT NOT NULL CHECK(severity IN ('INFO','WARNING','ERROR','CRITICAL')),actor_user_id UUID,resource_type TEXT,resource_id UUID,message TEXT NOT NULL,metadata JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS analytics_daily_snapshot (snapshot_date DATE PRIMARY KEY,assessments_started INTEGER NOT NULL DEFAULT 0,assessments_completed INTEGER NOT NULL DEFAULT 0,reports_draft INTEGER NOT NULL DEFAULT 0,reports_in_review INTEGER NOT NULL DEFAULT 0,reports_approved INTEGER NOT NULL DEFAULT 0,reports_released INTEGER NOT NULL DEFAULT 0,active_therapists INTEGER NOT NULL DEFAULT 0,active_parents INTEGER NOT NULL DEFAULT 0,created_at TIMESTAMPTZ NOT NULL DEFAULT now());

-- PHASE 13: compatibility migration for existing installations
ALTER TABLE therapists ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'THERAPIST';
ALTER TABLE therapists ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='therapists_role_check') THEN
    ALTER TABLE therapists ADD CONSTRAINT therapists_role_check CHECK(role IN ('ADMIN','THERAPIST'));
  END IF;
END $$;
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
-- AUTIBLOOM Phase 13.4: Clinical Data Security Hardening
CREATE TABLE IF NOT EXISTS parent_security_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  parent_id UUID NOT NULL REFERENCES parent_users(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_parent_security_audit_parent_created ON parent_security_audit(parent_id, created_at DESC);

-- Faster object-level authorization paths used by therapist/parent report access.
CREATE INDEX IF NOT EXISTS idx_assessments_therapist_id ON assessments(therapist_id, id);
CREATE INDEX IF NOT EXISTS idx_clinical_reports_therapist_id ON clinical_reports(therapist_id, id);
CREATE INDEX IF NOT EXISTS idx_parent_child_links_parent_verified ON parent_child_links(parent_id, verified_at, child_id);
CREATE INDEX IF NOT EXISTS idx_parent_child_links_child_verified ON parent_child_links(child_id, verified_at, parent_id);

-- Clean up consumed/expired authentication tokens without exposing token values.
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_expiry ON email_verification_tokens(expires_at) WHERE used_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expiry ON password_reset_tokens(expires_at) WHERE used_at IS NULL;

-- AUTIBLOOM PHASE 13.5: mandatory MFA for ADMIN/THERAPIST accounts.
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
