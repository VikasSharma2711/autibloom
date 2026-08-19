CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE therapists(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
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

CREATE EXTENSION IF NOT EXISTS pgcrypto;
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
