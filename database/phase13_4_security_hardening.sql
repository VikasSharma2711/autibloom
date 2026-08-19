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
