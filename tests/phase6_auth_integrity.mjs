import assert from "node:assert/strict";
import fs from "node:fs";
const schema=fs.readFileSync(new URL("../database/schema.sql",import.meta.url),"utf8");
const server=fs.readFileSync(new URL("../backend/server.js",import.meta.url),"utf8");
const auth=fs.readFileSync(new URL("../backend/auth.js",import.meta.url),"utf8");
for(const x of ["CREATE TABLE IF NOT EXISTS user_sessions","CREATE TABLE IF NOT EXISTS parent_users","CREATE TABLE IF NOT EXISTS parent_child_links"])assert(schema.includes(x));
for(const x of ["/api/v1/auth/register","/api/v1/auth/login","/api/v1/auth/logout","/api/v1/auth/me","/api/v1/auth/change-password","requirePhase6Auth","autibloom_session","HttpOnly","SameSite=Lax","/api/v1/children","/api/v1/assessments"])assert(server.includes(x));
for(const x of ["hashSessionToken","createSessionToken","sessionExpiry","isStrongPassword"])assert(auth.includes(x));
console.log("PHASE 6 AUTH INTEGRITY PASSED");
