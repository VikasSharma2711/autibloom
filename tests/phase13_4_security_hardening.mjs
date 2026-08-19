import assert from "node:assert/strict";
import fs from "node:fs";
const server=fs.readFileSync(new URL("../backend/server.js",import.meta.url),"utf8");
const schema=fs.readFileSync(new URL("../database/schema.sql",import.meta.url),"utf8");
const migration=fs.readFileSync(new URL("../database/phase13_4_security_hardening.sql",import.meta.url),"utf8");

// Authentication hardening
for (const x of [
  "AUTH_LIMITS", "authRateLimit", "RATE_LIMITED",
  "If the account is eligible, verification instructions will be sent to this email address.",
  "if(!u.email_verified_at)return res.status(401).json({error:\"INVALID_CREDENTIALS\"})",
  "if(!p.email_verified_at)return res.status(401).json({error:\"INVALID_CREDENTIALS\"})",
  "UPDATE user_sessions SET revoked_at=now() WHERE therapist_id=$1 AND revoked_at IS NULL",
  "reauthentication_required:true"
]) assert(server.includes(x), `missing: ${x}`);

// Parent security audit trail
for (const x of [
  "parent_security_audit", "REGISTER_PENDING_EMAIL", "EMAIL_VERIFIED",
  "LOGIN_SUCCESS", "LOGOUT", "PASSWORD_RESET"
]) assert(server.includes(x), `missing parent audit: ${x}`);

// Object-level authorization invariants
for (const x of [
  "WHERE a.id=$1 AND a.therapist_id=$2",
  "WHERE r.id=$1 AND r.therapist_id=$2",
  "WHERE r.id=$1 AND pcl.parent_id=$2 AND pcl.verified_at IS NOT NULL AND r.status='Released'",
  "PARENT_NOT_VERIFIED_FOR_CHILD"
]) assert(server.includes(x), `missing authorization guard: ${x}`);

for (const x of [
  "parent_security_audit", "idx_assessments_therapist_id",
  "idx_clinical_reports_therapist_id", "idx_parent_child_links_parent_verified",
  "idx_parent_child_links_child_verified"
]) assert(migration.includes(x), `missing migration item: ${x}`);

// Sensitive response bodies must not expose passwords/tokens from auth endpoints.
for (const forbidden of ["password_hash", "RESEND_API_KEY"]) {
  assert(!server.includes(`res.json({${forbidden}`), `unsafe response: ${forbidden}`);
}

console.log("PHASE 13.4 SECURITY HARDENING INTEGRITY PASSED");
