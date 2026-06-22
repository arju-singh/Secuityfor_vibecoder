// Severity weights and grade computation shared by both scanners.

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const WEIGHTS = { critical: 40, high: 20, medium: 8, low: 3, info: 0 };

export function summarize(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (counts[f.severity] === undefined) counts.info++;
    else counts[f.severity]++;
  }
  return counts;
}

// Score starts at 100 and is reduced by weighted penalties (with diminishing
// returns so one category of many low findings cannot dominate critical ones).
export function scoreFindings(findings) {
  const counts = summarize(findings);
  let penalty = 0;
  for (const sev of SEVERITY_ORDER) {
    const n = counts[sev];
    if (!n) continue;
    // Diminishing returns: full weight for first, then sqrt-scaled additions.
    penalty += WEIGHTS[sev] * (1 + Math.sqrt(Math.max(0, n - 1)));
  }
  const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  return { score, grade: gradeFor(score), counts };
}

function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  if (score >= 30) return 'E';
  return 'F';
}
