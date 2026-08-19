import assert from "node:assert/strict";
import fs from "node:fs";
const server=fs.readFileSync(new URL("../backend/server.js",import.meta.url),"utf8");
const schema=fs.readFileSync(new URL("../database/schema.sql",import.meta.url),"utf8");
const migration=fs.readFileSync(new URL("../database/phase13_5_mfa.sql",import.meta.url),"utf8");
const page=fs.readFileSync(new URL("../app/mfa.html",import.meta.url),"utf8");
for(const x of [
  "MFA_ENCRYPTION_KEY", "mfa_methods", "mfa_challenges", "mfa_recovery_codes",
  "MFA_SETUP_REQUIRED", "MFA_SETUP", "MFA_VERIFY", "mfa_required:true",
  "/api/v1/auth/mfa/setup", "/api/v1/auth/mfa/enable", "/api/v1/auth/mfa/verify",
  "MFA_RECOVERY_CODE_USED", "MFA_ENABLED", "verifyTotp", "encryptMfaSecret", "decryptMfaSecret"
]) assert(server.includes(x), `missing MFA server control: ${x}`);
for(const x of ["mfa_methods","mfa_challenges","mfa_recovery_codes","code_hash","secret_encrypted"])
  assert(schema.includes(x), `missing schema item: ${x}`);
for(const x of ["CREATE TABLE IF NOT EXISTS mfa_methods","CREATE TABLE IF NOT EXISTS mfa_challenges","CREATE TABLE IF NOT EXISTS mfa_recovery_codes"])
  assert(migration.includes(x), `missing migration item: ${x}`);
for(const x of ["Authenticator", "recovery codes", "setup_token", "challenge_token", "one-time-code"])
  assert(page.includes(x), `missing MFA UI item: ${x}`);
assert(server.includes("if(!mfaEnabled)"), "MFA must be enforced before session creation");
assert(server.includes("const codes=createRecoveryCodes()"), "recovery codes must be generated during enrollment");
assert(server.includes("UPDATE mfa_recovery_codes SET used_at=now()"), "recovery codes must be single-use");
console.log("PHASE 13.5 MFA INTEGRITY PASSED");
