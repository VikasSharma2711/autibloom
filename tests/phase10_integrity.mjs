import assert from 'node:assert/strict';import fs from 'node:fs';
const s=fs.readFileSync(new URL('../backend/server.js',import.meta.url),'utf8');
const q=fs.readFileSync(new URL('../clinical/AUTIBLOOM_Scoring_Matrix_V1.csv',import.meta.url),'utf8').replace(/^\uFEFF/,'');
assert.equal(q.trim().split(/\r?\n/).length-1,121);
assert.match(s,/\/api\/v1\/therapist\/dashboard/);
assert.match(s,/SUBMITTED_FOR_REVIEW/);
assert.match(s,/REPORT_NOT_READY_FOR_RELEASE/);
assert.match(s,/PARENT_PORTAL/);
console.log('AUTIBLOOM Phase 10 integrity checks PASSED');
