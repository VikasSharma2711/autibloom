-- AUTIBLOOM PHASE 9: Parent Portal & Secure Report Delivery
CREATE TABLE IF NOT EXISTS parent_sessions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 parent_id UUID NOT NULL REFERENCES parent_users(id) ON DELETE CASCADE,
 session_hash TEXT NOT NULL UNIQUE,
 expires_at TIMESTAMPTZ NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_parent_sessions_hash ON parent_sessions(session_hash);
CREATE TABLE IF NOT EXISTS report_delivery_tokens (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 report_id UUID NOT NULL REFERENCES clinical_reports(id) ON DELETE CASCADE,
 parent_id UUID NOT NULL REFERENCES parent_users(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE,
 expires_at TIMESTAMPTZ NOT NULL,
 first_viewed_at TIMESTAMPTZ,
 revoked_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_report_delivery_report ON report_delivery_tokens(report_id);
CREATE INDEX IF NOT EXISTS idx_report_delivery_parent ON report_delivery_tokens(parent_id);
CREATE TABLE IF NOT EXISTS report_download_log (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 report_id UUID NOT NULL REFERENCES clinical_reports(id) ON DELETE CASCADE,
 parent_id UUID REFERENCES parent_users(id) ON DELETE SET NULL,
 actor_type TEXT NOT NULL CHECK(actor_type IN ('therapist','parent')),
 action TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
