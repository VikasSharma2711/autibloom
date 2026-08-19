-- AUTIBLOOM PHASE 10: Therapist Clinical Review & Release
CREATE TABLE IF NOT EXISTS clinical_report_reviews (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 report_id UUID NOT NULL REFERENCES clinical_reports(id) ON DELETE CASCADE,
 therapist_id UUID NOT NULL REFERENCES therapist_users(id) ON DELETE RESTRICT,
 action TEXT NOT NULL CHECK(action IN ('DRAFT_SAVED','SUBMITTED_FOR_REVIEW','APPROVED','RETURNED','RELEASED')),
 note TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_clinical_report_reviews_report ON clinical_report_reviews(report_id);
CREATE TABLE IF NOT EXISTS clinical_report_release_log (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 report_id UUID NOT NULL REFERENCES clinical_reports(id) ON DELETE CASCADE,
 therapist_id UUID NOT NULL REFERENCES therapist_users(id) ON DELETE RESTRICT,
 release_channel TEXT NOT NULL CHECK(release_channel IN ('PARENT_PORTAL','INTERNAL')),
 released_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_release_log_report ON clinical_report_release_log(report_id);
