-- AUTIBLOOM Phase 7 schema hardening
ALTER TABLE therapists ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
CREATE INDEX IF NOT EXISTS idx_assessments_therapist_started ON assessments(therapist_id,started_at DESC);
CREATE INDEX IF NOT EXISTS idx_responses_assessment_question ON responses(assessment_id,question_id);
