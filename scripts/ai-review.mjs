// AI pull-request reviewer using the Claude API. Reads the PR diff, asks Claude
// for a concise, actionable review, and posts it as a PR comment. Activates only
// when ANTHROPIC_API_KEY is set — otherwise it no-ops so CI stays green.
//
// Env (set by the workflow): ANTHROPIC_API_KEY, GITHUB_TOKEN, GITHUB_REPOSITORY,
// PR_NUMBER, BASE_SHA, HEAD_SHA, optional AI_REVIEW_MODEL.
import { execSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';

const KEY = process.env.ANTHROPIC_API_KEY;
const MODEL = process.env.AI_REVIEW_MODEL || 'claude-sonnet-4-6';
const { PR_NUMBER: PR, GITHUB_REPOSITORY: REPO, GITHUB_TOKEN: GH, BASE_SHA, HEAD_SHA } = process.env;

if (!KEY) { console.log('No ANTHROPIC_API_KEY set — skipping AI review.'); process.exit(0); }
if (!PR || !REPO || !GH) { console.log('Missing PR context — skipping.'); process.exit(0); }

// Diff of the PR vs its base (exclude noisy/generated files).
let diff = '';
try {
  diff = execSync(
    `git diff ${BASE_SHA}...${HEAD_SHA} -- . ':(exclude)package-lock.json' ':(exclude)*.woff2' ':(exclude)*.min.js'`,
    { maxBuffer: 25 * 1024 * 1024 }
  ).toString();
} catch (e) {
  console.error('Could not compute diff:', e.message); process.exit(0);
}
if (!diff.trim()) { console.log('Empty diff — nothing to review.'); process.exit(0); }
if (diff.length > 60000) diff = diff.slice(0, 60000) + '\n…[diff truncated for length]…';

// Optional project config: custom guidelines + path-specific instructions.
let cfg = {};
if (existsSync('.ai-review.json')) {
  try { cfg = JSON.parse(readFileSync('.ai-review.json', 'utf8')); }
  catch (e) { console.log('Ignoring invalid .ai-review.json:', e.message); }
}
const guidelines = Array.isArray(cfg.guidelines) && cfg.guidelines.length
  ? '\nProject coding guidelines to enforce:\n' + cfg.guidelines.map((g) => `- ${g}`).join('\n') : '';
const pathRules = Array.isArray(cfg.pathInstructions) && cfg.pathInstructions.length
  ? '\nPath-specific instructions:\n' + cfg.pathInstructions.map((p) => `- ${p.path}: ${p.instructions}`).join('\n') : '';

const prompt = `You are a senior software engineer reviewing a pull request. Be concise and actionable.

Return Markdown with these sections:
1. **Summary** — 2-3 sentences on what the PR changes and why.
2. **Walkthrough** — a compact table of each changed file and what changed in it.
3. **Diagram** — ONLY if the change alters control/data flow across files, include a Mermaid diagram in a \`\`\`mermaid block; otherwise omit this section.
4. **Findings** — a bulleted list. For each: \`file:line\` if identifiable, a severity tag (**blocker** / **major** / **minor** / **nit**), the issue, and a concrete fix. Prioritise real bugs, security, and correctness over style. Where a fix is small, include a committable \`\`\`suggestion block.
5. If nothing significant, say "✅ No blocking issues found."

Review only what the diff shows. Do not invent files.${guidelines}${pathRules}

DIFF:
\`\`\`diff
${diff}
\`\`\``;

const res = await fetch('https://api.anthropic.com/v1/messages', {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-api-key': KEY, 'anthropic-version': '2023-06-01' },
  body: JSON.stringify({ model: MODEL, max_tokens: 2000, messages: [{ role: 'user', content: prompt }] })
});
const data = await res.json();
if (!res.ok) { console.error('Anthropic API error:', JSON.stringify(data).slice(0, 800)); process.exit(1); }
const review = (data.content || []).map((b) => b.text || '').join('\n').trim() || '_No review produced._';

const body = `## 🤖 AI Code Review\n\n${review}\n\n<sub>Automated review by SentryScan AI · model \`${MODEL}\` · advisory only — a human should still review.</sub>`;

const post = await fetch(`https://api.github.com/repos/${REPO}/issues/${PR}/comments`, {
  method: 'POST',
  headers: { authorization: `Bearer ${GH}`, accept: 'application/vnd.github+json', 'content-type': 'application/json' },
  body: JSON.stringify({ body })
});
if (!post.ok) { console.error('Posting PR comment failed:', post.status, (await post.text()).slice(0, 400)); process.exit(1); }
console.log(`Posted AI review to PR #${PR}.`);
