/**
 * Repo check: is this GitHub repository safe to clone and run?
 * Built for the "take-home test" and "run our bot" scams, where a fake recruiter or project sends a repo that
 * steals wallets and browser passwords the moment it is installed or opened.
 *   - Install hooks: package.json preinstall / postinstall / prepare scripts, setup.py commands, and VS Code
 *     tasks that run when the folder is opened (runOn: folderOpen).
 *   - Code that fetches and runs code: eval or new Function on downloaded text, base64 or hex blobs fed to eval,
 *     child_process running curl / PowerShell, Python exec of decoded strings.
 *   - Theft targets: wallet extension ids and folders, browser login and cookie databases, keychains,
 *     Discord and Telegram webhooks used to send stolen data.
 *   - Obfuscation: obfuscator.io names, very long lines hidden past the edge of the editor.
 *   - The account and stars: owner account age, repo age vs stars, and whether recent stargazers are
 *     brand-new empty accounts (bought stars).
 * Reads the repo through the GitHub API and raw files; nothing is cloned or run.
 */
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { signalId } from '../core/text.js';
import { postJson } from '../sources/press.js';

export interface RepoFinding { file: string; line: number | null; what: string; severity: 'high' | 'medium' | 'low'; excerpt: string | null }

export interface RepoReport {
  repo: string;
  url: string;
  verdict: 'malicious code found' | 'suspicious' | 'no known risk found';
  risk: number;
  findings: RepoFinding[];
  account: { login: string; type: string; createdAt: string | null; ageDays: number | null; repos: number | null; followers: number | null } | null;
  stats: { stars: number; forks: number; createdAt: string; pushedAt: string; ageDays: number; files: number; scanned: number; fork: boolean; archived: boolean; license: string | null };
  stars: { sampled: number; newAccounts: number; emptyAccounts: number } | null;
  reasons: string[];
  advice: string[];
}

const DAY = 86_400_000;
const CODE = /\.(m?js|cjs|ts|tsx|jsx|py|sh|ps1|bat|cmd|vbs)$/i;
const BINARY = /\.(exe|dll|scr|msi|jar|apk|bin|so|dylib|node|pyc)$/i;
const PRIORITY = /(^|\/)(package\.json|setup\.py|pyproject\.toml|\.vscode\/tasks\.json|\.vscode\/settings\.json|requirements\.txt|install\.(sh|ps1|py|js)|(tailwind|postcss|next|vite|webpack|babel|hardhat|truffle|jest|eslint)\.config\.(c|m)?js|server\.js|index\.js|app\.js|main\.js|main\.py|bot\.py|run\.py|start\.(sh|js)|config\.js)$/i;

const PATTERNS: [RegExp, string, RepoFinding['severity']][] = [
  [/\beval\s*\(\s*(atob|Buffer\.from|decodeURIComponent|unescape)\s*\(/, 'eval of decoded text: hides code from readers', 'high'],
  [/new\s+Function\s*\(\s*(atob|Buffer\.from|[a-z_$][\w$]*\.data\b|response|res\b)/i, 'builds a function from downloaded or decoded text', 'high'],
  [/\.then\s*\(\s*\(?\s*\w*\s*\)?\s*=>\s*(eval|new Function)\b|\beval\s*\(\s*\w+\.(data|text|body)\b/, 'runs code downloaded from the internet', 'high'],
  [/child_process[\s\S]{0,200}\b(curl|wget|powershell|iwr|Invoke-WebRequest|bitsadmin|certutil|mshta)\b/i, 'starts a shell that downloads something', 'high'],
  [/\b(exec|execSync|spawn)\s*\(\s*['"`][^'"`]*\b(curl|wget|powershell|iex|Invoke-Expression)\b/i, 'runs curl or PowerShell from the code', 'high'],
  [/exec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex)/, 'Python exec of a decoded string', 'high'],
  [/exec\s*\(\s*requests\.get\(|exec\s*\(\s*urllib/, 'Python exec of downloaded code', 'high'],
  [/nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|ejbalbakoplchlghecdalmeeeajnimhm|hnfanknocfeofbddgcijnmhnfnkdnaad|ibnejdfjmmkpcnlpebklmnkoeoihofec|fhbohimaelbohpjbbldcngcnapndodjp/, 'reads crypto wallet extension data (MetaMask, Phantom, Coinbase, TronLink...)', 'high'],
  [/Local Extension Settings|Login Data|Web Data['"]|\\Cookies['"]|Network[\\/]+Cookies|Local State['"]/, 'reads browser password, cookie or extension databases', 'high'],
  [/Exodus[\\/]exodus\.wallet|Electrum[\\/]wallets|\.config[\\/]solana[\\/]id\.json|Atomic[\\/]Local Storage|keychain-db|login\.keychain/i, 'reads wallet files or the keychain', 'high'],
  [/discord(app)?\.com\/api\/webhooks\/\d+|api\.telegram\.org\/bot\d+:[\w-]{20,}/, 'sends data to a Discord or Telegram webhook', 'medium'],
  [/_0x[0-9a-f]{4,6}\b[\s\S]*_0x[0-9a-f]{4,6}\b[\s\S]*_0x[0-9a-f]{4,6}\b/, 'obfuscated with obfuscator.io (_0x names)', 'medium'],
  [/['"`][A-Za-z0-9+/]{400,}={0,2}['"`]/, 'large base64 blob in the code', 'medium'],
  [/(\\x[0-9a-f]{2}){40,}/i, 'long hex-escaped string', 'medium'],
  [/\bprocess\.env\b[\s\S]{0,80}\b(axios|fetch|request)\s*\.?\s*(post|\()/, 'sends environment variables (keys, tokens) somewhere', 'medium'],
  [/require\(\s*['"]os['"]\s*\)[\s\S]{0,400}(homedir|hostname)[\s\S]{0,400}(axios|fetch|https?\.request)/, 'collects machine details and sends them out', 'medium'],
];

interface Gh { stargazers_count: number; forks_count: number; created_at: string; pushed_at: string; fork: boolean; archived: boolean; default_branch: string; license?: { spdx_id?: string } | null; owner: { login: string; type: string }; html_url: string; full_name: string }

export function parseRepo(input: string): string {
  const s = input.trim().replace(/\.git$/, '').replace(/\/+$/, '');
  const m = /^(?:https?:\/\/)?(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+)/i.exec(s) ?? /^([\w.-]+)\/([\w.-]+)$/.exec(s);
  if (!m) throw new Error('give a GitHub repository: owner/name or a github.com link');
  return `${m[1]}/${m[2]}`;
}

export function scanText(file: string, text: string): RepoFinding[] {
  const out: RepoFinding[] = [];
  const lines = text.split(/\r?\n/);
  const minified = /\.min\.js$/.test(file) || (lines.length < 5 && text.length > 20_000);
  for (const [re, what, severity] of PATTERNS) {
    if (minified && severity !== 'high') continue;
    const m = re.exec(text);
    if (!m) continue;
    const line = text.slice(0, m.index).split('\n').length;
    out.push({ file, line, what, severity, excerpt: m[0].slice(0, 120) });
  }
  if (!minified) {
    const i = lines.findIndex((l) => /^\s{200,}\S/.test(l) || /\S\s{300,}\S/.test(l));
    if (i >= 0) out.push({ file, line: i + 1, what: 'code hidden far to the right of the screen after a run of spaces', severity: 'high', excerpt: lines[i]!.trim().slice(0, 120) });
  }
  if (/(^|\/)package\.json$/.test(file)) {
    try {
      const p = JSON.parse(text) as { scripts?: Record<string, string>; dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      for (const h of ['preinstall', 'install', 'postinstall', 'prepare', 'prestart', 'predev']) {
        const cmd = p.scripts?.[h];
        if (!cmd) continue;
        const bad = /curl|wget|powershell|node\s+-e|base64|http|\|\s*(sh|bash)/i.test(cmd);
        if (bad || /install|prepare/.test(h)) out.push({ file, line: null, what: `"${h}" script runs on install: ${cmd.slice(0, 100)}`, severity: bad ? 'high' : /^(husky|husky install|tsc|npm run build|node-gyp rebuild|patch-package)/.test(cmd.trim()) ? 'low' : 'medium', excerpt: null });
      }
      for (const [n, v] of Object.entries({ ...p.dependencies, ...p.devDependencies })) {
        if (/^(https?:|git\+|github:)/.test(v) && !/github\.com\/(npm|nodejs|microsoft|facebook|vercel)\//.test(v)) out.push({ file, line: null, what: `dependency ${n} comes from a URL, not the npm registry (${v.slice(0, 80)})`, severity: 'medium', excerpt: null });
      }
    } catch { /* not JSON */ }
  }
  if (/\.vscode\/tasks\.json$/.test(file) && /"runOn"\s*:\s*"folderOpen"/.test(text)) out.push({ file, line: null, what: 'a VS Code task runs by itself when the folder is opened', severity: 'high', excerpt: (/"command"\s*:\s*"([^"]{0,100})/.exec(text)?.[1]) ?? null });
  if (/setup\.py$/.test(file) && /cmdclass|os\.system|subprocess/.test(text)) out.push({ file, line: null, what: 'setup.py runs commands during install', severity: /curl|wget|http|base64|exec\(/.test(text) ? 'high' : 'medium', excerpt: null });
  return out;
}

export async function repoCheck(ctx: Ctx, input: string): Promise<ModuleResult<RepoReport>> {
  const repo = parseRepo(input);
  const tok = key('GITHUB_TOKEN');
  const headers: Record<string, string> = { accept: 'application/vnd.github+json', ...(tok ? { authorization: `Bearer ${tok}` } : {}) };
  const provenance: Provenance[] = [];
  const r = await ctx.http.get<Gh>(`https://api.github.com/repos/${repo}`, { source: 'github', headers, ttlSec: 1800 });
  provenance.push(r.prov);
  if (!r.data) throw new Error(r.prov.note === 'HTTP 404' ? `no public repository ${repo} on GitHub` : `GitHub is not answering (${r.prov.note ?? r.prov.status})`);
  const g = r.data;
  const nowMs = ctx.now().getTime();
  const [u, tree] = await Promise.all([
    ctx.http.get<{ login: string; type: string; created_at?: string; public_repos?: number; followers?: number }>(`https://api.github.com/users/${g.owner.login}`, { source: 'github', headers, ttlSec: 86_400 }),
    ctx.http.get<{ tree?: { path: string; type: string; size?: number }[]; truncated?: boolean }>(`https://api.github.com/repos/${repo}/git/trees/${encodeURIComponent(g.default_branch)}?recursive=1`, { source: 'github', headers, ttlSec: 1800 }),
  ]);
  provenance.push(tree.prov);
  const files = (tree.data?.tree ?? []).filter((f) => f.type === 'blob');
  const findings: RepoFinding[] = [];
  for (const f of files.filter((x) => BINARY.test(x.path)).slice(0, 5)) findings.push({ file: f.path, line: null, what: `program file committed to the repo (${f.path.split('.').pop()})`, severity: /\.(exe|scr|dll|msi)$/i.test(f.path) ? 'high' : 'medium', excerpt: null });
  if (files.some((f) => f.path.startsWith('node_modules/'))) findings.push({ file: 'node_modules/', line: null, what: 'node_modules is committed: packages in it can be modified and run without coming from npm', severity: 'medium', excerpt: null });

  // Which files to read: install hooks and configs first, then small code files near the root.
  const pick = [
    ...files.filter((f) => PRIORITY.test(f.path)),
    ...files.filter((f) => CODE.test(f.path) && !PRIORITY.test(f.path) && !/node_modules\/|\/(test|tests|__tests__|dist|build|vendor)\//.test(f.path)).sort((a, b) => a.path.split('/').length - b.path.split('/').length || (a.size ?? 0) - (b.size ?? 0)),
  ].filter((f) => (f.size ?? 0) < 400_000).slice(0, 40);
  let scanned = 0;
  for (let i = 0; i < pick.length; i += 8) {
    const got = await Promise.all(pick.slice(i, i + 8).map((f) => ctx.http.get<string>(`https://raw.githubusercontent.com/${repo}/${encodeURIComponent(g.default_branch)}/${f.path.split('/').map(encodeURIComponent).join('/')}`, { source: 'github-raw', as: 'text', ttlSec: 1800, retries: 0 }).then((x) => [f.path, x] as const)));
    if (i === 0 && got[0]) provenance.push(got[0][1].prov);
    for (const [p, x] of got) if (typeof x.data === 'string') { scanned++; findings.push(...scanText(p, x.data)); }
  }

  // Account and stars.
  const acc = u.data ? { login: u.data.login, type: u.data.type, createdAt: u.data.created_at ?? null, ageDays: u.data.created_at ? Math.floor((nowMs - Date.parse(u.data.created_at)) / DAY) : null, repos: u.data.public_repos ?? null, followers: u.data.followers ?? null } : null;
  let stars: RepoReport['stars'] = null;
  if (tok && g.stargazers_count >= 20) {
    const [owner, name] = repo.split('/');
    const q = await postJson<{ data?: { repository?: { stargazers?: { nodes?: { createdAt: string; repositories: { totalCount: number }; followers: { totalCount: number } }[] } } } }>(ctx, 'https://api.github.com/graphql', { query: 'query($o:String!,$n:String!){repository(owner:$o,name:$n){stargazers(last:60){nodes{createdAt repositories{totalCount} followers{totalCount}}}}}', variables: { o: owner, n: name } }, { authorization: `Bearer ${tok}` }, 'github-graphql', 3600);
    let nodes = q.data?.data?.repository?.stargazers?.nodes ?? [];
    // Fine-grained tokens cannot read stargazers over GraphQL: sample the newest stars over REST instead.
    if (!nodes.length && g.stargazers_count <= 40_000) {
      const page = Math.max(1, Math.ceil(g.stargazers_count / 30));
      const list = await ctx.http.get<{ login: string }[]>(`https://api.github.com/repos/${repo}/stargazers?per_page=30&page=${page}`, { source: 'github', headers, ttlSec: 3600 });
      const logins = (Array.isArray(list.data) ? list.data : []).slice(-20).map((x) => x.login);
      const users = await Promise.all(logins.map((l) => ctx.http.get<{ created_at?: string; public_repos?: number; followers?: number }>(`https://api.github.com/users/${l}`, { source: 'github', headers, ttlSec: 7 * 86_400 })));
      nodes = users.filter((x) => x.data?.created_at).map((x) => ({ createdAt: x.data!.created_at!, repositories: { totalCount: x.data!.public_repos ?? 0 }, followers: { totalCount: x.data!.followers ?? 0 } }));
    }
    if (nodes.length) stars = { sampled: nodes.length, newAccounts: nodes.filter((n) => nowMs - Date.parse(n.createdAt) < 60 * DAY).length, emptyAccounts: nodes.filter((n) => n.repositories.totalCount === 0 && n.followers.totalCount === 0).length };
  }

  const ageDays = Math.floor((nowMs - Date.parse(g.created_at)) / DAY);
  const reasons: string[] = [];
  const high = findings.filter((f) => f.severity === 'high'), med = findings.filter((f) => f.severity === 'medium');
  for (const f of [...high, ...med].slice(0, 8)) reasons.push(`${f.file}${f.line ? `:${f.line}` : ''}: ${f.what}`);
  let risk = high.length * 40 + med.length * 12;
  if (acc?.ageDays !== null && acc?.ageDays !== undefined && acc.ageDays < 30) { risk += 15; reasons.push(`the owner account is ${acc.ageDays} days old`); }
  if (stars && stars.sampled >= 15 && (stars.newAccounts + stars.emptyAccounts) / (2 * stars.sampled) > 0.5) { risk += 20; reasons.push(`${stars.newAccounts} of the last ${stars.sampled} stars come from accounts younger than 60 days, ${stars.emptyAccounts} from empty accounts: likely bought stars`); }
  if (ageDays < 14 && g.stargazers_count > 300) { risk += 10; reasons.push(`${g.stargazers_count} stars on a repo only ${ageDays} days old`); }
  risk = Math.min(100, risk);
  const verdict: RepoReport['verdict'] = high.length ? 'malicious code found' : risk >= 25 ? 'suspicious' : 'no known risk found';
  const advice = verdict === 'malicious code found'
    ? ['Do not install, run or open this repo in your editor. If you already did, assume wallets, browser passwords and SSH keys on that machine are stolen: move funds to a new wallet from another device and change passwords.', 'Report the repo to GitHub (Report repository).']
    : verdict === 'suspicious' ? ['Read the flagged files before running anything. Run it in a throwaway virtual machine or a GitHub Codespace, never on the machine with your wallet.']
      : ['No known malicious patterns in the files read. That is not a guarantee: run code from strangers in a throwaway environment.'];
  const now = ctx.now().toISOString();
  const signals: Signal[] = high.length ? [{ id: signalId('repo', repo.toLowerCase()), module: 'repo', title: `GitHub repo ${repo}: ${high[0]!.what}`, score: Math.min(95, 60 + high.length * 10), entity: `repo:${repo.toLowerCase()}`, evidence: high.slice(0, 3).map((f) => ({ source: 'github', text: `${f.file}: ${f.what}`, url: `${g.html_url}/blob/${g.default_branch}/${f.file}` })), createdAt: now }] : [];
  return {
    module: 'repo', input: repo, generatedAt: now,
    result: { repo: g.full_name, url: g.html_url, verdict, risk, findings: findings.slice(0, 40), account: acc, stats: { stars: g.stargazers_count, forks: g.forks_count, createdAt: g.created_at, pushedAt: g.pushed_at, ageDays, files: files.length, scanned, fork: g.fork, archived: g.archived, license: g.license?.spdx_id ?? null }, stars, reasons, advice },
    signals, provenance,
  };
}
