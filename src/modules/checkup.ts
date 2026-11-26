/**
 * Security Checkup: a 0-100 score from what the browser already measured (password in breach lists, how well
 * the email domain is protected against spoofing, breaches known for that domain, risky wallet approvals) and
 * six habit answers. Pure and deterministic: the server never sees the password, the full email or anything
 * personal, only the answers and counts below.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult } from '../core/types.js';

export interface CheckupInput {
  password?: { pwned: boolean; count?: number } | null;
  emailDomain?: { verdict: 'spoofable' | 'partly protected' | 'protected' } | null;
  domainBreaches?: number | null;
  wallet?: { riskyApprovals: number } | null;
  habits?: {
    passwordManager?: 'yes' | 'no';
    twoFactor?: 'key' | 'app' | 'sms' | 'none';
    uniquePasswords?: 'all' | 'most' | 'few';
    simLock?: 'yes' | 'unsure' | 'no';
    updates?: 'auto' | 'sometimes' | 'rarely';
    backups?: 'yes' | 'sometimes' | 'no';
  };
}

export interface CheckupItem { id: string; label: string; answer: string; points: number; max: number; fix: string | null }
export interface CheckupResult { score: number; grade: 'A' | 'B' | 'C' | 'D' | 'F'; points: number; max: number; items: CheckupItem[]; topFixes: { id: string; fix: string; gain: number }[]; note: string }

type Rule = { label: string; max: number; values: Record<string, number>; fix: Record<string, string> };

const HABITS: Record<keyof NonNullable<CheckupInput['habits']>, Rule> = {
  twoFactor: {
    label: 'Two-step sign-in', max: 15, values: { key: 15, app: 12, sms: 6, none: 0 },
    fix: { app: 'Add a passkey or security key to your email and bank, the strongest form of two-step sign-in.', sms: 'Switch two-step sign-in from text messages to an authenticator app or passkey; texts can be stolen by SIM swap.', none: 'Turn on two-step sign-in for your email first, then your bank and social accounts.' },
  },
  uniquePasswords: {
    label: 'A different password for every account', max: 15, values: { all: 15, most: 8, few: 0 },
    fix: { most: 'Replace the passwords you reuse, starting with email and banking.', few: 'Stop reusing passwords: one leak opens every account that shares it. Start with email and banking.' },
  },
  passwordManager: {
    label: 'Password manager', max: 12, values: { yes: 12, no: 0 },
    fix: { no: 'Use a password manager (the one built into your browser or phone is fine). It makes unique passwords easy and will not fill them in on look-alike sites.' },
  },
  updates: {
    label: 'Software updates', max: 10, values: { auto: 10, sometimes: 5, rarely: 0 },
    fix: { sometimes: 'Turn on automatic updates for your phone, computer and browser.', rarely: 'Turn on automatic updates for your phone, computer and browser; most attacks use holes that are already fixed.' },
  },
  simLock: {
    label: 'SIM lock or port-out PIN', max: 8, values: { yes: 8, unsure: 2, no: 0 },
    fix: { unsure: 'Ask your mobile carrier whether a SIM or port-out lock is on, and set a SIM PIN on your phone.', no: 'Ask your mobile carrier for a SIM or port-out lock, and set a SIM PIN on your phone, so nobody can move your number.' },
  },
  backups: {
    label: 'Backups', max: 8, values: { yes: 8, sometimes: 4, no: 0 },
    fix: { sometimes: 'Make backups automatic, so a lost phone or ransomware does not cost you your files.', no: 'Turn on automatic backups of your phone and computer (cloud or an external drive).' },
  },
};

export const GRADE_MIN: [CheckupResult['grade'], number][] = [['A', 90], ['B', 80], ['C', 70], ['D', 60], ['F', 0]];
export const gradeFor = (score: number): CheckupResult['grade'] => GRADE_MIN.find(([, m]) => score >= m)![0];

const nonNeg = (n: unknown, what: string): number => {
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0) throw new Error(`${what} must be a number of 0 or more`);
  return Math.floor(v);
};

export function scoreCheckup(input: CheckupInput): CheckupResult {
  const items: CheckupItem[] = [];
  if (input.password) {
    const count = nonNeg(input.password.count ?? 0, 'password.count');
    const pwned = Boolean(input.password.pwned) || count > 0;
    items.push({ id: 'password', label: 'Password not in breach lists', answer: pwned ? `found ${count ? `${count.toLocaleString('en-US')} times ` : ''}in breach lists` : 'not found', points: pwned ? 0 : 20, max: 20, fix: pwned ? 'Change the password you checked everywhere you use it: it is in breach lists that attackers try first.' : null });
  }
  if (input.emailDomain) {
    const v = input.emailDomain.verdict;
    const pts = { protected: 6, 'partly protected': 3, spoofable: 0 }[v];
    if (pts === undefined) throw new Error('emailDomain.verdict must be spoofable, partly protected or protected');
    items.push({ id: 'emailDomain', label: 'Email domain protected against spoofing', answer: v, points: pts, max: 6, fix: pts < 6 ? 'Mail claiming to be from your email domain can be forged. Be extra careful with messages that seem to come from your own provider; if you own the domain, set DMARC to quarantine or reject.' : null });
  }
  if (input.domainBreaches != null) {
    const n = nonNeg(input.domainBreaches, 'domainBreaches');
    const pts = n === 0 ? 6 : n <= 2 ? 3 : 0;
    items.push({ id: 'domainBreaches', label: 'Breaches known for your email domain', answer: String(n), points: pts, max: 6, fix: n ? 'Your email domain has had breaches: make sure that account has a unique password and two-step sign-in.' : null });
  }
  if (input.wallet) {
    const n = nonNeg(input.wallet.riskyApprovals, 'wallet.riskyApprovals');
    const pts = n === 0 ? 10 : n <= 2 ? 5 : 0;
    items.push({ id: 'wallet', label: 'Risky wallet approvals', answer: String(n), points: pts, max: 10, fix: n ? `Revoke the ${n} risky approval${n === 1 ? '' : 's'} on your wallet in Wallet Guard (/guard).` : null });
  }
  const h = input.habits ?? {};
  for (const [id, rule] of Object.entries(HABITS) as [keyof typeof HABITS, Rule][]) {
    const a = h[id];
    if (a == null) continue;
    const pts = rule.values[a];
    if (pts === undefined) throw new Error(`habits.${id} must be one of ${Object.keys(rule.values).join(', ')}`);
    items.push({ id, label: rule.label, answer: a, points: pts, max: rule.max, fix: rule.fix[a] ?? null });
  }
  if (!items.length) throw new Error('nothing to score: answer at least one question');
  const points = items.reduce((s, i) => s + i.points, 0);
  const max = items.reduce((s, i) => s + i.max, 0);
  const score = Math.round((points / max) * 100);
  const topFixes = items.filter((i) => i.fix).map((i) => ({ id: i.id, fix: i.fix!, gain: Math.round(((i.max - i.points) / max) * 100) }))
    .sort((a, b) => b.gain - a.gain);
  return { score, grade: gradeFor(score), points, max, items, topFixes, note: items.length < 10 ? 'Questions you skipped are left out, and the score is scaled to the ones you answered.' : 'Every question answered.' };
}

export async function checkup(ctx: Ctx, input: CheckupInput): Promise<ModuleResult<CheckupResult>> {
  const r = scoreCheckup(input ?? {});
  return {
    module: 'checkup',
    input: `${r.items.length} answers`,
    generatedAt: ctx.now().toISOString(),
    result: r,
    signals: [],
    provenance: [{ source: 'oculon-checkup', url: 'https://oculon.live/checkup', status: 'LIVE', fetchedAt: ctx.now().toISOString(), note: 'deterministic scoring of the answers given; nothing stored' }],
  };
}

/** Parse a card path part like "B-84"; the grade must match the score so a card cannot claim more than it shows. */
export function parseCard(part: string): { grade: CheckupResult['grade']; score: number } | null {
  const m = /^([ABCDF])-(\d{1,3})$/.exec(part);
  if (!m) return null;
  const score = Number(m[2]);
  if (score > 100 || gradeFor(score) !== m[1]) return null;
  return { grade: m[1] as CheckupResult['grade'], score };
}

/** A 1200x630 share card with only the grade and the score. Returns null for a grade that does not fit the score. */
export function checkupCardSvg(grade: string, score: number): string | null {
  const p = parseCard(`${grade}-${score}`);
  if (!p) return null;
  const col = { A: '#3ddc97', B: '#3ddc97', C: '#ffb84d', D: '#ffb84d', F: '#ff5d6c' }[p.grade];
  const arc = Math.max(0.001, p.score / 100);
  const r = 150, cx = 900, cy = 315, a = arc * 2 * Math.PI - Math.PI / 2;
  const x = cx + r * Math.cos(a), y = cy + r * Math.sin(a);
  const path = p.score >= 100 ? `M ${cx} ${cy - r} A ${r} ${r} 0 1 1 ${cx - 0.01} ${cy - r}` : `M ${cx} ${cy - r} A ${r} ${r} 0 ${arc > 0.5 ? 1 : 0} 1 ${x.toFixed(2)} ${y.toFixed(2)}`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img" aria-label="Security Checkup grade ${p.grade}, score ${p.score} of 100">
<rect width="1200" height="630" fill="#000"/>
<rect x="24" y="24" width="1152" height="582" fill="none" stroke="#1f2a2d" stroke-width="2"/>
<text x="80" y="120" fill="#00f0ff" font-family="Consolas, 'Space Mono', monospace" font-size="26" letter-spacing="8">OCULON</text>
<text x="80" y="230" fill="#fff" font-family="'Space Grotesk', Arial, sans-serif" font-size="68" font-weight="300">Security Checkup</text>
<text x="80" y="300" fill="#9a9a9a" font-family="'Space Grotesk', Arial, sans-serif" font-size="30">Passwords, sign-in, phone, updates, backups.</text>
<text x="80" y="345" fill="#9a9a9a" font-family="'Space Grotesk', Arial, sans-serif" font-size="30">Five minutes, nothing personal sent.</text>
<text x="80" y="540" fill="#cfcfcf" font-family="Consolas, 'Space Mono', monospace" font-size="28">oculon.live/checkup</text>
<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#1f2a2d" stroke-width="22"/>
<path d="${path}" fill="none" stroke="${col}" stroke-width="22" stroke-linecap="round"/>
<text x="${cx}" y="${cy + 40}" text-anchor="middle" fill="${col}" font-family="'Space Grotesk', Arial, sans-serif" font-size="150" font-weight="600">${p.grade}</text>
<text x="${cx}" y="${cy + 230}" text-anchor="middle" fill="#fff" font-family="Consolas, 'Space Mono', monospace" font-size="40">${p.score} / 100</text>
</svg>`;
}
