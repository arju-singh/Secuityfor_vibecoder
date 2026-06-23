// PR chat: answers questions about a pull request's diff when someone comments
// "@sentryscan <question>". Uses the Claude API; no-ops without ANTHROPIC_API_KEY.
// Env: ANTHROPIC_API_KEY, GITHUB_TOKEN, GITHUB_REPOSITORY, PR_NUMBER, COMMENT_BODY.
const KEY = process.env.ANTHROPIC_API_KEY;
const MODEL = process.env.AI_REVIEW_MODEL || 'claude-sonnet-4-6';
const { PR_NUMBER: PR, GITHUB_REPOSITORY: REPO, GITHUB_TOKEN: GH, COMMENT_BODY = '' } = process.env;

if (!KEY) { console.log('No ANTHROPIC_API_KEY — skipping.'); process.exit(0); }
if (!/@sentryscan\b/i.test(COMMENT_BODY)) { console.log('No @sentryscan trigger — skipping.'); process.exit(0); }
if (!PR || !REPO || !GH) { console.log('Missing PR context — skipping.'); process.exit(0); }

const question = COMMENT_BODY.replace(/@sentryscan/gi, '').trim() || 'Give a quick review of this PR.';

const dres = await fetch(`https://api.github.com/repos/${REPO}/pulls/${PR}`, {
  headers: { authorization: `Bearer ${GH}`, accept: 'application/vnd.github.v3.diff' }
});
let diff = await dres.text();
if (!dres.ok) { console.error('Could not fetch PR diff:', dres.status); process.exit(1); }
if (diff.length > 60000) diff = diff.slice(0, 60000) + '\n…[diff truncated]…';

const prompt = `You are answering a question about a GitHub pull request, given its diff. Be concise and specific; cite \`file:line\` where relevant. If the diff doesn't contain the answer, say so plainly.

QUESTION: ${question}

DIFF:
\`\`\`diff
${diff}
\`\`\``;

const res = await fetch('https://api.anthropic.com/v1/messages', {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-api-key': KEY, 'anthropic-version': '2023-06-01' },
  body: JSON.stringify({ model: MODEL, max_tokens: 1500, messages: [{ role: 'user', content: prompt }] })
});
const data = await res.json();
if (!res.ok) { console.error('Anthropic API error:', JSON.stringify(data).slice(0, 800)); process.exit(1); }
const answer = (data.content || []).map((b) => b.text || '').join('\n').trim() || '_No answer produced._';

const body = `**@sentryscan:**\n\n${answer}\n\n<sub>SentryScan AI · model \`${MODEL}\` · advisory.</sub>`;
const post = await fetch(`https://api.github.com/repos/${REPO}/issues/${PR}/comments`, {
  method: 'POST',
  headers: { authorization: `Bearer ${GH}`, accept: 'application/vnd.github+json', 'content-type': 'application/json' },
  body: JSON.stringify({ body })
});
if (!post.ok) { console.error('Posting reply failed:', post.status, (await post.text()).slice(0, 400)); process.exit(1); }
console.log(`Replied to PR #${PR}.`);
