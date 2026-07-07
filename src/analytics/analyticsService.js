// Aggregate analytics ("VART" — Vulnerability Analytics & Reporting) over ALL of
// a signed-in user's saved scans. Pure, in-process, owner-scoped: it reads the
// scan/dismissal stores and computes a security-posture rollup. It makes NO
// network calls and never returns a raw secret — every finding that leaves here
// is masked. buildAnalytics(email) is the single entry point behind
// GET /api/analytics.
import { listScans } from '../projects/scanStore.js';
import { getDismissals } from '../projects/dismissalStore.js';
import { findingFingerprint } from '../projects/fingerprint.js';
import { scoreFindings, summarize, SEVERITY_ORDER } from '../scanners/scoring.js';
import { maskFinding } from './mask.js';

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CONF_RANK = { high: 0, medium: 1, low: 2 };

const OWASP_NAMES = {
  A01: 'Broken Access Control',
  A02: 'Cryptographic Failures',
  A03: 'Injection',
  A04: 'Insecure Design',
  A05: 'Security Misconfiguration',
  A06: 'Vulnerable & Outdated Components',
  A07: 'Identification & Authentication Failures',
  A08: 'Software & Data Integrity Failures',
  A09: 'Security Logging & Monitoring Failures',
  A10: 'Server-Side Request Forgery (SSRF)'
};

const CATEGORY_LABELS = {
  ui: 'UI / health', security: 'Security', vuln: 'Vulnerabilities & OWASP',
  render: 'JavaScript / render', perf: 'Performance', a11y: 'Accessibility',
  seo: 'SEO', api: 'API checks', access: 'Access control', spec: 'API surface',
  fuzz: 'Parameter fuzzing', vapt: 'Active pen-test (VAPT)', code: 'Source code',
  quality: 'Code quality', frontend: 'Frontend quality', config: 'Config & DevOps',
  testing: 'Testing quality', hygiene: 'Project hygiene', deps: 'Dependencies'
};
const labelFor = (c) => CATEGORY_LABELS[c] || (c ? c[0].toUpperCase() + c.slice(1) : 'Other');

function owaspCode(f) {
  const m = typeof f.owasp === 'string' ? f.owasp.match(/A\d{2}/) : null;
  return m ? m[0] : null;
}

// The current open-issues set: newest scan per distinct target, unioned and
// de-duplicated by fingerprint, with the user's dismissals annotated. Mirrors the
// per-project rollup in server.js but spans every project/target the user has.
function currentFindings(scans, dismissals) {
  const latestByTarget = new Map();
  for (const s of scans) { // scans are newest-first
    if (!latestByTarget.has(s.target)) latestByTarget.set(s.target, s);
  }
  const seen = new Map();
  for (const s of latestByTarget.values()) {
    for (const f of s.findings || []) {
      const fp = findingFingerprint(f);
      if (seen.has(fp)) continue;
      const d = dismissals[fp];
      seen.set(fp, { ...f, fingerprint: fp, scanId: s.id, fromTarget: s.target, project: s.project, dismissed: d ? d.reason : null });
    }
  }
  return [...seen.values()];
}

function countBy(items, keyFn) {
  const m = new Map();
  for (const it of items) {
    const k = keyFn(it);
    if (k == null) continue;
    m.set(k, (m.get(k) || 0) + 1);
  }
  return m;
}

function projectRollup(scans, dismissals) {
  const byProject = new Map();
  for (const s of scans) {
    if (!byProject.has(s.project)) byProject.set(s.project, []);
    byProject.get(s.project).push(s);
  }
  return [...byProject.entries()].map(([name, list]) => {
    const sorted = [...list].sort((a, b) => a.ts.localeCompare(b.ts)); // oldest→newest
    const latest = sorted[sorted.length - 1];
    const open = currentFindings(list, dismissals).filter((f) => !f.dismissed);
    return {
      name,
      scanCount: list.length,
      lastScanAt: latest ? latest.ts : null,
      latest: latest ? { grade: latest.grade, score: latest.score } : null,
      open: summarize(open),
      openTotal: open.length,
      trend: sorted.slice(-20).map((s) => ({ ts: s.ts, score: s.score }))
    };
  }).sort((a, b) => (b.lastScanAt || '').localeCompare(a.lastScanAt || ''));
}

export function buildAnalytics(ownerEmail) {
  const scans = listScans(ownerEmail); // newest-first, all projects
  const dismissals = getDismissals(ownerEmail);
  const generatedAt = new Date().toISOString();

  if (!scans.length) {
    return { ok: true, empty: true, generatedAt, totals: { scans: 0, projects: 0, targets: 0, findings: 0, open: 0, dismissed: 0 } };
  }

  const current = currentFindings(scans, dismissals);
  const open = current.filter((f) => !f.dismissed);
  const dismissedCount = current.length - open.length;

  const { score, grade } = scoreFindings(open);
  const severity = summarize(open);

  const owaspBreakdown = [...countBy(open, owaspCode).entries()]
    .map(([code, count]) => ({ code, name: OWASP_NAMES[code] || code, count }))
    .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));

  const categoryBreakdown = [...countBy(open, (f) => f.category).entries()]
    .map(([category, count]) => ({ category, label: labelFor(category), count }))
    .sort((a, b) => b.count - a.count);

  const confidence = { high: 0, medium: 0, low: 0 };
  for (const f of open) if (confidence[f.confidence] !== undefined) confidence[f.confidence]++;

  // Full chronological score trend across every scan (oldest→newest), capped.
  const trend = [...scans]
    .sort((a, b) => a.ts.localeCompare(b.ts))
    .slice(-60)
    .map((s) => ({ ts: s.ts, score: s.score, grade: s.grade, project: s.project, target: s.target }));

  // Ranked remediation priority: severity first, then confidence, then a stable
  // title tiebreak. Masked so no raw secret is surfaced.
  const topFindings = [...open]
    .sort((a, b) =>
      (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) ||
      (CONF_RANK[a.confidence] ?? 9) - (CONF_RANK[b.confidence] ?? 9) ||
      String(a.title).localeCompare(String(b.title)))
    .slice(0, 20)
    .map((f) => {
      const m = maskFinding(f);
      return {
        fingerprint: f.fingerprint, severity: f.severity, confidence: f.confidence,
        category: f.category, categoryLabel: labelFor(f.category),
        owasp: owaspCode(f), title: m.title, impact: m.impact,
        remediation: m.remediation, evidence: m.evidence,
        target: f.fromTarget, project: f.project
      };
    });

  const distinctTargets = new Set(scans.map((s) => s.target)).size;
  const distinctProjects = new Set(scans.map((s) => s.project)).size;

  return {
    ok: true,
    empty: false,
    generatedAt,
    totals: {
      scans: scans.length,
      projects: distinctProjects,
      targets: distinctTargets,
      findings: current.length,
      open: open.length,
      dismissed: dismissedCount
    },
    posture: { score, grade, severity },
    severityOrder: SEVERITY_ORDER,
    severity,
    owaspBreakdown,
    categoryBreakdown,
    confidence,
    trend,
    projects: projectRollup(scans, dismissals),
    topFindings
  };
}
