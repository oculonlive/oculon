/**
 * Breaches, from Have I Been Pwned (keyless parts, CC BY 4.0, attribution: haveibeenpwned.com).
 *   Password check: Pwned Passwords with k-anonymity. Only the first 5 characters of the password's SHA-1
 *     hash leave this machine; the match happens locally, and the password is never stored or logged.
 *   Breach list: the newest breaches added to HIBP, or every breach of one domain.
 */
import { createHash } from 'node:crypto';
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance, Sourced } from '../core/types.js';

export interface PasswordCheck { pwned: boolean; count: number; prefix: string; advice: string[] }

export interface Breach {
  name: string;
  title: string;
  domain: string | null;
  breachDate: string | null;
  addedDate: string | null;
  accounts: number;
  dataClasses: string[];
  verified: boolean;
  spamList: boolean;
  malware: boolean;
  description: string;
  url: string;
}

export interface BreachList { query: string | null; total: number; breaches: Breach[]; note: string }

const ATTRIBUTION = 'Breach data from Have I Been Pwned (haveibeenpwned.com), CC BY 4.0.';

export const sha1Hex = (s: string) => createHash('sha1').update(s, 'utf8').digest('hex').toUpperCase();

/** Suffix counts for one 5-character SHA-1 prefix; padding rows (count 0) are dropped. */
export async function pwnedRange(ctx: Ctx, prefix: string): Promise<Sourced<Map<string, number>>> {
  const p = prefix.toUpperCase();
  if (!/^[0-9A-F]{5}$/.test(p)) throw new Error('prefix must be the first 5 hex characters of a SHA-1 hash');
  const r = await ctx.http.get<string>(`https://api.pwnedpasswords.com/range/${p}`, { source: 'pwned-passwords', as: 'text', ttlSec: 7 * 86_400, headers: { 'Add-Padding': 'true' } });
  if (!r.data) return { data: null, prov: r.prov };
  const m = new Map<string, number>();
  for (const line of r.data.split(/\r?\n/)) {
    const [suf, n] = line.split(':');
    const c = Number(n);
    if (suf && c > 0) m.set(suf.trim().toUpperCase(), c);
  }
  return { data: m, prov: r.prov };
}

/** Is this password in known breaches? Pass the password itself, or "sha1:<40 hex>". */
export async function passwordCheck(ctx: Ctx, password: string): Promise<ModuleResult<PasswordCheck>> {
  if (!password) throw new Error('missing password');
  const pre = /^sha1:([0-9a-f]{40})$/i.exec(password.trim());
  const hash = pre ? pre[1]!.toUpperCase() : sha1Hex(password);
  const r = await pwnedRange(ctx, hash.slice(0, 5));
  if (!r.data) throw new Error(`Pwned Passwords is not answering right now (${r.prov.note ?? r.prov.status})`);
  const count = r.data.get(hash.slice(5)) ?? 0;
  const advice = count
    ? ['Stop using this password everywhere you use it, starting with email and banking.', 'Use a password manager to create a different password for every site, and turn on two-factor sign-in.']
    : ['Not in any known breach. Still use it on one site only, and keep two-factor sign-in on.'];
  return {
    module: 'password',
    // The input is never echoed: results are shown, cached and shared without the password.
    input: 'password (hidden)',
    generatedAt: ctx.now().toISOString(),
    result: { pwned: count > 0, count, prefix: hash.slice(0, 5), advice },
    signals: [],
    provenance: [{ ...r.prov, note: 'only the first 5 characters of the SHA-1 hash were sent' }],
  };
}

interface RawBreach { Name?: string; Title?: string; Domain?: string; BreachDate?: string; AddedDate?: string; PwnCount?: number; DataClasses?: string[]; IsVerified?: boolean; IsSensitive?: boolean; IsRetired?: boolean; IsSpamList?: boolean; IsMalware?: boolean; IsFabricated?: boolean; Description?: string }

const strip = (html: string) => html.replace(/<[^>]+>/g, '').replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&#39;|&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/\s+/g, ' ').trim();

export function toBreach(x: RawBreach): Breach {
  const d = strip(x.Description ?? '');
  return {
    name: x.Name ?? '',
    title: x.Title ?? x.Name ?? '',
    domain: x.Domain || null,
    breachDate: x.BreachDate ?? null,
    addedDate: x.AddedDate?.slice(0, 10) ?? null,
    accounts: Number(x.PwnCount ?? 0),
    dataClasses: (x.DataClasses ?? []).slice(0, 12),
    verified: x.IsVerified !== false,
    spamList: x.IsSpamList === true,
    malware: x.IsMalware === true,
    description: d.length > 360 ? `${d.slice(0, 359)}…` : d,
    url: `https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(x.Name ?? '')}`,
  };
}

/** Newest breaches, or the breaches of one domain or company name. Sensitive, retired and fabricated breaches are left out. */
export async function breaches(ctx: Ctx, input = ''): Promise<ModuleResult<BreachList>> {
  const q = input.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '');
  const r = await ctx.http.get<RawBreach[]>('https://haveibeenpwned.com/api/v3/breaches', {
    source: 'hibp',
    ttlSec: 6 * 3600,
    timeoutMs: 30_000,
    keep: (d: RawBreach[]) => (Array.isArray(d) ? d.filter((x) => !x.IsSensitive && !x.IsRetired && !x.IsFabricated).map((x) => ({ Name: x.Name, Title: x.Title, Domain: x.Domain, BreachDate: x.BreachDate, AddedDate: x.AddedDate, PwnCount: x.PwnCount, DataClasses: x.DataClasses, IsVerified: x.IsVerified, IsSpamList: x.IsSpamList, IsMalware: x.IsMalware, Description: (x.Description ?? '').slice(0, 1500) })) : []),
  });
  const provenance: Provenance[] = [r.prov];
  if (!r.data) throw new Error(`Have I Been Pwned is not answering right now (${r.prov.note ?? r.prov.status})`);
  const all = r.data.map(toBreach);
  const hits = q
    ? all.filter((b) => (b.domain && (b.domain === q || b.domain.endsWith(`.${q}`))) || b.name.toLowerCase() === q || b.title.toLowerCase() === q || (q.length >= 4 && !q.includes('.') && b.title.toLowerCase().includes(q)))
    : all;
  const sorted = [...hits].sort((a, b) => (q ? (b.breachDate ?? '').localeCompare(a.breachDate ?? '') : (b.addedDate ?? '').localeCompare(a.addedDate ?? '')));
  return {
    module: 'breaches',
    input: q,
    generatedAt: ctx.now().toISOString(),
    result: {
      query: q || null,
      total: hits.length,
      breaches: sorted.slice(0, q ? 25 : 12),
      note: `${q ? (hits.length ? 'Breaches of this domain or company in Have I Been Pwned.' : 'No breach of this domain or company in Have I Been Pwned. Breaches nobody has published are not covered.') : 'The newest breaches added to Have I Been Pwned.'} ${ATTRIBUTION}`,
    },
    signals: [],
    provenance,
  };
}
