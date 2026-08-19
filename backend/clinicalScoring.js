import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Use the directory of *this* file (backend/) rather than process.cwd(),
// so the path is correct regardless of where the server is started from.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const matrixPath = path.resolve(__dirname, "../clinical/AUTIBLOOM_Scoring_Matrix_V1.csv");
const raw = fs.readFileSync(matrixPath, "utf8").replace(/^\uFEFF/, "");
const lines = raw.split(/\r?\n/).filter(Boolean);
const headers = lines.shift().split(",");

function parseCsvLine(line) {
  const out=[]; let cur=""; let quoted=false;
  for (let i=0;i<line.length;i++) {
    const c=line[i];
    if (c === '"') {
      if (quoted && line[i+1] === '"') { cur+='"'; i++; }
      else quoted=!quoted;
    } else if (c === "," && !quoted) { out.push(cur); cur=""; }
    else cur+=c;
  }
  out.push(cur);
  return out;
}

const matrix = lines.map(line => {
  const values=parseCsvLine(line), item={};
  headers.forEach((h,i)=>item[h]=values[i] ?? "");
  return item;
});

if (matrix.length !== 121 || new Set(matrix.map(q=>q.id)).size !== 121) {
  throw new Error("AUTIBLOOM_V1_MATRIX_INTEGRITY_FAILURE");
}

const questionIds = new Set(matrix.map(q=>q.id));

export function validateResponses(responses) {
  const keys=Object.keys(responses);
  if (keys.length !== 121) return false;
  return keys.every(id =>
    questionIds.has(id) &&
    (responses[id] === "na" || [0,1,2,3,4].includes(responses[id]))
  );
}

export function scoreResponses(responses) {
  if (!validateResponses(responses)) throw new Error("INVALID_RESPONSE_SET");

  const output={domain:{},pattern:{},functional_area:{}};

  for (const dimension of Object.keys(output)) {
    const groups={};
    for (const q of matrix) {
      const label=q[dimension];
      (groups[label] ??= []).push([
        responses[q.id],
        Number(q.functional_impact_weight || 1)
      ]);
    }
    for (const [label, items] of Object.entries(groups)) {
      const usable=items.filter(([v])=>v !== "na");
      if (!usable.length) { output[dimension][label]=null; continue; }
      const denominator=usable.reduce((s,[,w])=>s+w*4,0);
      const numerator=usable.reduce((s,[v,w])=>s+Number(v)*w,0);
      output[dimension][label]=Math.round(numerator/denominator*100);
    }
  }

  output.priorities=Object.entries(output.domain)
    .filter(([,v])=>v !== null)
    .sort((a,b)=>b[1]-a[1])
    .slice(0,5);

  output.instrument_version="AUTIBLOOM_V1";
  return output;
}
