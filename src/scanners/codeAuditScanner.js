// Native static-analysis audits for uploaded code — code quality, performance
// anti-patterns, frontend quality, config/DevOps, testing quality, project
// hygiene, and AI-hallucinated/undeclared imports. Pattern-based and
// dependency-free (no SonarQube/ESLint binary required); findings are signals.
import { finding } from './util.js';

const CODE_EXT = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue', 'svelte']);
const TEXT_EXT = new Set([...CODE_EXT, 'json', 'html', 'css', 'md', 'yml', 'yaml', 'txt', 'env', 'dockerfile']);
const FE_EXT = new Set(['jsx', 'tsx', 'vue', 'svelte', 'html']);
const NODE_BUILTINS = new Set(['fs', 'path', 'http', 'https', 'crypto', 'os', 'url', 'util', 'stream', 'events', 'child_process', 'net', 'tls', 'zlib', 'buffer', 'process', 'assert', 'dns', 'querystring', 'readline', 'cluster', 'worker_threads', 'async_hooks', 'perf_hooks', 'timers', 'string_decoder', 'v8', 'vm', 'module', 'console']);

function isBinary(buf) {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}
const count = (re, s) => (s.match(re) || []).length;

export function scanCodeAudit(entries) {
  const files = [];
  let pkg = null, gitignore = null, tsconfig = null, dockerfile = null;
  const paths = [];

  for (const e of entries) {
    const path = e.path.replace(/\\/g, '/');
    paths.push(path);
    const base = (path.split('/').pop() || '').toLowerCase();
    const ext = base.includes('.') ? base.split('.').pop() : (/dockerfile/.test(base) ? 'dockerfile' : '');
    if (!e.buffer || isBinary(e.buffer) || e.buffer.length > 600_000) continue;
    const content = e.buffer.toString('utf8');
    if (base === 'package.json') { try { pkg = JSON.parse(content); } catch { /* ignore */ } }
    else if (base === '.gitignore') gitignore = content;
    else if (base === 'tsconfig.json') tsconfig = content;
    else if (/^dockerfile/.test(base)) dockerfile = content;
    if (TEXT_EXT.has(ext) || base.startsWith('.env')) {
      files.push({ path, base, ext, content, lines: content.split('\n').length, isTest: /\.(test|spec)\.|(^|\/)(tests?|__tests__|e2e)\//i.test(path) });
    }
  }

  return {
    quality: qualityChecks(files, pkg),
    frontend: frontendChecks(files),
    config: configChecks(files, tsconfig, dockerfile),
    testing: testingChecks(files),
    hygiene: hygieneChecks(paths, gitignore, pkg)
  };
}

// ---- Code quality + performance anti-patterns + hallucinated imports -------
function qualityChecks(files, pkg) {
  const f = [];
  const code = files.filter((x) => CODE_EXT.has(x.ext));

  const godFiles = code.filter((x) => x.lines > 300).map((x) => `${x.path} (${x.lines} lines)`);
  if (godFiles.length) f.push(finding('medium', `${godFiles.length} oversized file(s) (>300 lines)`,
    'Large files usually do too much and are hard to maintain.', 'Split into focused modules.', godFiles.slice(0, 6).join('\n')));

  let godModules = 0, todos = 0, empties = 0, commented = 0, awaitMap = 0, syncIO = 0, jsonLoop = 0;
  for (const x of code) {
    if (count(/^\s*export\b/gm, x.content) >= 20) godModules++;
    todos += count(/\b(TODO|FIXME)\b|not\s+implemented|throw new Error\(\s*['"][^'"]*not implemented/gi, x.content);
    empties += count(/=>\s*\{\s*\}|function\s+\w*\s*\([^)]*\)\s*\{\s*\}/g, x.content);
    commented += commentedBlocks(x.content);
    awaitMap += count(/\.map\(\s*async\b/g, x.content);
    syncIO += count(/\b(readFileSync|writeFileSync|appendFileSync|execSync)\b/g, x.content);
    jsonLoop += loopWith(x.content, /JSON\.(parse|stringify)\(/);
  }
  if (godModules) f.push(finding('medium', `${godModules} "god module(s)" with 20+ exports`, 'Modules exporting 20+ symbols are a monolith smell.', 'Group related exports into cohesive modules.'));
  if (todos) f.push(finding('low', `${todos} TODO/FIXME/"not implemented" marker(s)`, 'Unfinished work or placeholder stubs remain in the code.', 'Resolve or track these before shipping.'));
  if (empties) f.push(finding('low', `${empties} empty function bodies`, 'Placeholder functions with no implementation give false confidence.', 'Implement or remove empty functions.'));
  if (commented) f.push(finding('low', `${commented} block(s) of commented-out code`, 'Dead code in comments adds noise and confusion.', 'Delete commented-out code; rely on version control.'));
  if (awaitMap) f.push(finding('medium', `${awaitMap} use(s) of await inside .map()`, 'await in .map() builds an array of promises that often run unintentionally or are not awaited.', 'Use Promise.all(arr.map(async …)) or a for…of loop.'));
  if (syncIO) f.push(finding('low', `${syncIO} synchronous I/O call(s) (…Sync)`, 'Synchronous file/exec calls block the event loop if used in request handling.', 'Use async variants outside startup code.'));
  if (jsonLoop) f.push(finding('low', `${jsonLoop} JSON parse/stringify inside a loop`, 'Repeated serialization inside loops is wasteful.', 'Move serialization out of the loop where possible.'));

  // AI-hallucinated / undeclared imports (needs package.json to compare).
  if (pkg) {
    const declared = new Set([...Object.keys(pkg.dependencies || {}), ...Object.keys(pkg.devDependencies || {}), ...Object.keys(pkg.peerDependencies || {}), ...Object.keys(pkg.optionalDependencies || {})]);
    const undeclared = new Set();
    for (const x of code) {
      for (const spec of collectImports(x.content)) {
        if (/^[./]/.test(spec) || spec.startsWith('node:')) continue;
        const name = pkgName(spec);
        if (!NODE_BUILTINS.has(name) && !declared.has(name)) undeclared.add(name);
      }
    }
    if (undeclared.size) f.push(finding('high', `${undeclared.size} undeclared / possibly AI-hallucinated import(s)`,
      'These packages are imported but not listed in package.json dependencies — they will fail to install/run, a common sign of AI-invented packages.',
      'Verify each package exists and add it to dependencies, or remove the import.', [...undeclared].slice(0, 12).join(', ')));
  }

  if (!f.length) f.push(finding('info', 'No major code-quality issues detected', 'Pattern-based quality checks passed.', 'For deep analysis, run SonarQube/ESLint in CI.'));
  return f;
}

// ---- Frontend quality (React/Vue/Svelte/HTML) ------------------------------
function frontendChecks(files) {
  const f = [];
  const fe = files.filter((x) => FE_EXT.has(x.ext));
  let noAlt = 0, blankRel = 0, heavy = 0, domInReact = 0, effectLeak = 0, mapNoKey = 0;
  for (const x of fe) {
    noAlt += count(/<img\b(?![^>]*\balt=)[^>]*>/gi, x.content);
    blankRel += count(/<a\b(?![^>]*\brel=)[^>]*target=["']_blank["'][^>]*>/gi, x.content);
    heavy += count(/import\s+\w+\s+from\s+['"](lodash|moment)['"]/g, x.content);
    if (/\.(jsx|tsx)$/.test(x.path)) domInReact += count(/document\.(getElementById|querySelector)\(/g, x.content);
    if (/useEffect\(/.test(x.content) && /(setInterval|addEventListener)\(/.test(x.content) && !/clearInterval|removeEventListener|return\s*\(\s*\)\s*=>/.test(x.content)) effectLeak++;
    mapNoKey += count(/\.map\([^)]*=>\s*<[A-Z][A-Za-z]*\b(?![^>]*\bkey=)/g, x.content);
  }
  if (noAlt) f.push(finding('medium', `${noAlt} <img> without alt text`, 'Images without alt are inaccessible to screen readers.', 'Add descriptive alt (or alt="" for decorative images).'));
  if (blankRel) f.push(finding('medium', `${blankRel} target="_blank" link(s) without rel="noopener"`, 'Opening links without rel="noopener" exposes window.opener to the new page (reverse tabnabbing).', 'Add rel="noopener noreferrer" to target="_blank" links.'));
  if (heavy) f.push(finding('medium', `${heavy} full import(s) of a heavy library (lodash/moment)`, 'Importing all of lodash/moment bloats the client bundle.', 'Import specific functions, or use lighter alternatives (date-fns).'));
  if (domInReact) f.push(finding('medium', `${domInReact} direct DOM access in React components`, 'document.getElementById/querySelector in React bypasses the virtual DOM.', 'Use refs (useRef) instead of direct DOM queries.'));
  if (effectLeak) f.push(finding('high', `${effectLeak} useEffect with timer/listener but no cleanup`, 'setInterval/addEventListener without a cleanup return leaks memory and fires after unmount.', 'Return a cleanup function from useEffect (clearInterval/removeEventListener).'));
  if (mapNoKey) f.push(finding('medium', `${mapNoKey} list render(s) without a key prop`, '.map() rendering components without key causes reconciliation bugs.', 'Add a stable, unique key to each rendered list item.'));
  if (!fe.length) return [finding('info', 'No frontend component files found', 'No JSX/Vue/Svelte/HTML files to audit.', 'N/A')];
  if (!f.length) f.push(finding('info', 'No major frontend issues detected', 'Frontend pattern checks passed.', 'Complement with React DevTools / Lighthouse.'));
  return f;
}

// ---- Config / DevOps -------------------------------------------------------
function configChecks(files, tsconfig, dockerfile) {
  const f = [];
  const code = files.filter((x) => CODE_EXT.has(x.ext) && !x.isTest);
  let localhost = 0, consoleLogs = 0;
  for (const x of code) {
    localhost += count(/['"`]https?:\/\/localhost(:\d+)?/g, x.content);
    consoleLogs += count(/\bconsole\.log\(/g, x.content);
  }
  if (localhost) f.push(finding('medium', `${localhost} hardcoded localhost URL(s)`, 'http://localhost in non-test code breaks in production.', 'Use an environment variable with a sensible fallback.'));
  if (consoleLogs >= 5) f.push(finding('low', `${consoleLogs} console.log call(s)`, 'Many console.log calls instead of a structured logger hurt observability.', 'Use a logger (pino/winston) with levels.'));
  if (dockerfile && /^FROM\s+\S+(:latest)?\s*$/im.test(dockerfile) && !/^FROM\s+\S+:(?!latest)\S+/im.test(dockerfile)) {
    f.push(finding('medium', 'Unpinned Docker base image (:latest or untagged)', 'Using :latest makes builds non-reproducible.', 'Pin the base image to a specific version/digest.'));
  }
  if (tsconfig && !/"strict"\s*:\s*true/.test(tsconfig)) {
    f.push(finding('medium', 'TypeScript strict mode disabled', 'Without "strict": true, implicit any and null-safety issues slip through.', 'Enable "strict": true in tsconfig.json.'));
  }
  // health endpoint, only meaningful for server projects
  const allCode = code.map((x) => x.content).join('\n');
  if (/\b(express|fastify|koa|@hapi|http\.createServer)\b/.test(allCode) && !/['"`]\/(health|healthz|livez|readyz)\b/.test(allCode)) {
    f.push(finding('low', 'No health-check endpoint', 'No /health or /healthz route for container orchestration / uptime checks.', 'Add a lightweight health endpoint.'));
  }
  if (!f.length) f.push(finding('info', 'No major configuration issues detected', 'Config/DevOps checks passed.', 'Review Dockerfile and tsconfig periodically.'));
  return f;
}

// ---- Testing quality -------------------------------------------------------
function testingChecks(files) {
  const f = [];
  const source = files.filter((x) => CODE_EXT.has(x.ext) && !x.isTest);
  const tests = files.filter((x) => x.isTest);
  if (!source.length) return [finding('info', 'No source files to evaluate testing for', '', 'N/A')];
  if (!tests.length) {
    f.push(finding('high', 'No tests found', 'The project has no test/spec files — regressions will go undetected.', 'Add unit and integration tests.'));
    return f;
  }
  const ratio = tests.length / source.length;
  if (ratio < 0.2) f.push(finding('medium', `Low test-to-source ratio (${tests.length}:${source.length})`, 'Few test files relative to source — likely thin coverage.', 'Increase test coverage of critical paths.'));
  let emptyTests = 0, noAssert = 0;
  for (const x of tests) {
    emptyTests += count(/\b(it|test)\(\s*['"][^'"]*['"]\s*,\s*(async\s*)?\(\s*\)\s*=>\s*\{\s*\}\s*\)/g, x.content);
    if (!/\b(expect|assert|should|chai|t\.is|t\.deepEqual)\b/.test(x.content)) noAssert++;
  }
  if (emptyTests) f.push(finding('high', `${emptyTests} empty test body(ies)`, 'Tests with empty bodies pass without checking anything — false confidence.', 'Implement real assertions or remove the test.'));
  if (noAssert) f.push(finding('medium', `${noAssert} test file(s) with no assertions`, 'Tests that never assert run code but verify nothing.', 'Add expect/assert calls.'));
  if (!f.length) f.push(finding('info', 'No major testing issues detected', `${tests.length} test file(s) found with assertions.`, 'Track coverage in CI.'));
  return f;
}

// ---- Project hygiene -------------------------------------------------------
function hygieneChecks(paths, gitignore, pkg) {
  const f = [];
  const lower = paths.map((p) => p.toLowerCase());
  const envCommitted = paths.filter((p) => /(^|\/)\.env(\.local|\.production|\.development)?$/i.test(p));
  if (envCommitted.length) f.push(finding('critical', '.env file present in the upload/repo', 'Committing .env risks exposing real secrets in version control.', 'Remove .env from the repo, rotate any exposed secrets, and gitignore it.', envCommitted.slice(0, 4).join('\n')));
  if (gitignore == null) f.push(finding('medium', 'No .gitignore', 'Without .gitignore, node_modules/.env/build artifacts can be committed.', 'Add a .gitignore covering node_modules, .env, dist/build.'));
  else {
    const missing = ['node_modules', '.env', 'dist', 'build'].filter((e) => !gitignore.includes(e));
    if (missing.length >= 2) f.push(finding('low', `.gitignore missing common entries (${missing.join(', ')})`, 'Important paths are not ignored and could be committed.', 'Add the missing entries to .gitignore.'));
  }
  if (!lower.some((p) => /(^|\/)readme(\.md|\.txt)?$/.test(p))) f.push(finding('medium', 'No README', 'No README to onboard developers.', 'Add a README describing setup and usage.'));
  if (pkg && !lower.some((p) => /\.env\.example$/.test(p))) {
    f.push(finding('low', 'No .env.example', 'New developers have no template for required environment variables.', 'Commit a .env.example listing required vars (no real values).'));
  }
  const hasLock = lower.some((p) => /(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(p));
  if (pkg && !hasLock) f.push(finding('high', 'No lock file', 'Missing package-lock/yarn.lock/pnpm-lock makes installs non-reproducible.', 'Commit a lock file.'));
  if (!f.length) f.push(finding('info', 'No major project-hygiene issues detected', 'Core hygiene checks passed.', 'Keep README and .gitignore current.'));
  return f;
}

// ---- helpers ---------------------------------------------------------------
function collectImports(content) {
  const out = new Set();
  let m;
  const re1 = /\bimport\s+(?:[^'";]*?\s+from\s+)?['"]([^'"]+)['"]/g;
  const re2 = /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g;
  while ((m = re1.exec(content))) out.add(m[1]);
  while ((m = re2.exec(content))) out.add(m[1]);
  return [...out];
}
function pkgName(spec) {
  if (spec.startsWith('@')) return spec.split('/').slice(0, 2).join('/');
  return spec.split('/')[0];
}
function commentedBlocks(content) {
  const lines = content.split('\n');
  let run = 0, blocks = 0;
  for (const ln of lines) {
    if (/^\s*\/\/.*[;{}()=<>]/.test(ln)) { run++; if (run === 3) blocks++; }
    else run = 0;
  }
  return blocks;
}
// True if a loop construct's body (next ~400 chars) contains `pattern`.
function loopWith(content, pattern) {
  let n = 0;
  const re = /\b(for|while)\b\s*\([^)]*\)\s*\{|\.(forEach|map|reduce)\(/g;
  let m;
  while ((m = re.exec(content))) {
    const slice = content.slice(m.index, m.index + 400);
    if (pattern.test(slice)) n++;
  }
  return n;
}
