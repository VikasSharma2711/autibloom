CREATE TABLE IF NOT EXISTS clinical_reports (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(), assessment_id UUID NOT NULL UNIQUE REFERENCES assessments(id) ON DELETE CASCADE,
therapist_id UUID NOT NULL REFERENCES therapists(id) ON DELETE RESTRICT, report_version TEXT NOT NULL,
status TEXT NOT NULL DEFAULT 'Draft' CHECK(status IN ('Draft','Reviewed','Released')),
clinical_summary JSONB NOT NULL DEFAULT '{}'::jsonb,parent_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,home_program JSONB NOT NULL DEFAULT '[]'::jsonb,
clinician_notes TEXT NOT NULL DEFAULT '',created_at TIMESTAMPTZ NOT NULL DEFAULT now(),updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
reviewed_at TIMESTAMPTZ,released_at TIMESTAMPTZ);
CREATE INDEX IF NOT EXISTS idx_clinical_reports_therapist ON clinical_reports(therapist_id,updated_at DESC);
CREATE TABLE IF NOT EXISTS report_access_log (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),report_id UUID NOT NULL REFERENCES clinical_reports(id) ON DELETE CASCADE,
actor_type TEXT NOT NULL CHECK(actor_type IN ('therapist','parent','system')),actor_id UUID,action TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS idx_report_access_log_report ON report_access_log(report_id,created_at DESC);
