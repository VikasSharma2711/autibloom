import assert from "node:assert/strict";
import fs from "node:fs";

const csv=fs.readFileSync(new URL("../clinical/AUTIBLOOM_Scoring_Matrix_V1.csv",import.meta.url),"utf8").replace(/^\uFEFF/,"");
const lines=csv.trim().split(/\r?\n/);
assert.equal(lines.length,122,"Expected header + 121 rows");

const ids=lines.slice(1).map(x=>x.split(",")[0]);
assert.equal(new Set(ids).size,121,"Question IDs must be unique");
assert.equal(ids[0],"AB-AU-001");
assert.equal(ids[120],"AB-EN-121");

const server=fs.readFileSync(new URL("../backend/server.js",import.meta.url),"utf8");
for (const token of [
  "PHASE5_RESPONSE_ROUTE",
  "PHASE5_COMPLETE_ROUTE",
  "scoreResponses",
  "validateResponses",
  "FOR UPDATE",
  "ASSESSMENT_COMPLETED",
  "status IN('Draft','In Progress')"
]) assert.match(server,new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")));

const db=fs.readFileSync(new URL("../database/schema.sql",import.meta.url),"utf8");
for(const table of ["therapists","children","assessments","responses","assessment_scores","audit_log"])
  assert.match(db,new RegExp("CREATE TABLE "+table));

console.log("AUTIBLOOM Phase 5 integrity tests PASSED");
