// GitHub repository scanner — downloads a public repo's zip archive and feeds it
// to the same code scanners. Built defensively:
//   • SSRF-safe: the URL is parsed to owner/repo only; the fetch host is HARD-CODED
//     to api.github.com (an attacker can't redirect it to internal services).
//   • Bomb-safe: the download is size-capped while streaming, and extraction caps
//     per-file size, total decompressed bytes, and file count.
//   • Read-only: it only GETs an archive; nothing is executed.
import AdmZip from 'adm-zip';
import { fetchWithTimeout } from './util.js';

const MAX_ZIP_BYTES = 40 * 1024 * 1024;        // 40 MB download cap
const MAX_TOTAL_BYTES = 80 * 1024 * 1024;      // 80 MB decompressed cap (bomb guard)
const MAX_FILE_BYTES = 2 * 1024 * 1024;        // skip individual files > 2 MB
const MAX_FILES = 5000;

// Accepts https://github.com/owner/repo[.git][/tree/<ref>]. Returns null otherwise.
export function parseRepoUrl(input) {
  const m = String(input || '').trim().match(
    /^https?:\/\/github\.com\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+?)(?:\.git)?(?:\/tree\/([A-Za-z0-9._\/-]+))?\/?$/i
  );
  if (!m) return null;
  return { owner: m[1], repo: m[2], ref: m[3] || '' };
}

async function downloadCapped(res, maxBytes) {
  const len = Number(res.headers.get('content-length') || 0);
  if (len && len > maxBytes) throw new Error(`Repository archive is too large (> ${Math.round(maxBytes / 1048576)} MB).`);
  if (!res.body || !res.body.getReader) return Buffer.from(await res.arrayBuffer());
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) { try { await reader.cancel(); } catch { /* ignore */ } throw new Error(`Repository archive is too large (> ${Math.round(maxBytes / 1048576)} MB).`); }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

// Extract a GitHub zipball into [{path, buffer}] with strict caps. GitHub wraps
// everything under "owner-repo-<sha>/", which we strip for clean paths.
export function safeExtract(buffer) {
  const zip = new AdmZip(buffer);
  const out = [];
  let total = 0;
  for (const e of zip.getEntries()) {
    if (e.isDirectory) continue;
    if (out.length >= MAX_FILES) break;
    const name = e.entryName.replace(/^[^/]+\//, ''); // drop the archive's top folder
    if (!name) continue;
    if (/(^|\/)(node_modules|\.next|dist|build|vendor|bower_components|\.git)\//i.test(name)) continue;
    const size = (e.header && e.header.size) || 0;
    if (size > MAX_FILE_BYTES) continue;        // skip oversized / bomb entries
    if (total + size > MAX_TOTAL_BYTES) break;  // total decompression cap
    total += size;
    out.push({ path: name, buffer: e.getData() });
  }
  return out;
}

export async function fetchRepoEntries(input) {
  const parsed = parseRepoUrl(input);
  if (!parsed) {
    const err = new Error('Provide a GitHub repository URL, e.g. https://github.com/owner/repo');
    err.status = 400; throw err;
  }
  const { owner, repo, ref } = parsed;
  // Host is fixed to api.github.com — the user only controls owner/repo/ref.
  const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/zipball/${ref ? ref.split('/').map(encodeURIComponent).join('/') : ''}`;
  const headers = { Accept: 'application/vnd.github+json' };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`; // optional: private repos / higher rate limit

  let res;
  try { res = await fetchWithTimeout(url, { timeout: 20000, redirect: 'follow', headers }); }
  catch (e) { const err = new Error(`Could not reach GitHub: ${e.message}`); err.status = 400; throw err; }

  if (res.status === 404) { const e = new Error('Repository not found, empty, or private (set GITHUB_TOKEN for private repos).'); e.status = 400; throw e; }
  if (res.status === 403) { const e = new Error('GitHub rate limit reached. Try again later or set GITHUB_TOKEN.'); e.status = 429; throw e; }
  if (!res.ok) { const e = new Error(`GitHub returned HTTP ${res.status}.`); e.status = 400; throw e; }

  const buf = await downloadCapped(res, MAX_ZIP_BYTES);
  const entries = safeExtract(buf);
  if (!entries.length) { const e = new Error('No analyzable source files found in the repository.'); e.status = 400; throw e; }
  return { meta: { repo: `${owner}/${repo}`, ref: ref || 'default branch', files: entries.length }, entries };
}
