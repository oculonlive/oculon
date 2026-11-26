/**
 * Invite link check: what is behind a Telegram or Discord link before you join it.
 *   Telegram (t.me/name, t.me/+invite, t.me/joinchat/...): the public preview page: title, description,
 *     members or subscribers, the verified badge, and Telegram's own scam or fake label.
 *   Discord (discord.gg/code, discord.com/invite/code): the public invite API: server name, members online and
 *     total, when the server was created (from its id), verification level, partner or verified status, expiry.
 * Flags the fake-support and fake-project pattern: a name that uses a known brand or "official", "support",
 * "airdrop", "claim" or "recovery" without the verified badge, on a new or small server.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';

export interface InviteReport {
  link: string;
  platform: 'telegram' | 'discord';
  verdict: 'labeled scam' | 'likely impersonation' | 'suspicious' | 'no known risk found' | 'invite not valid';
  risk: number;
  name: string | null;
  description: string | null;
  members: number | null;
  online: number | null;
  verified: boolean;
  createdAt: string | null;
  kind: string | null;
  reasons: string[];
  advice: string[];
}

const BRANDS = /\b(binance|coinbase|kraken|okx|bybit|kucoin|metamask|trust ?wallet|phantom|ledger|trezor|uniswap|opensea|pancakeswap|blur|magic ?eden|arbitrum|optimism|base|solana|ethereum|polygon|ton|tonkeeper|layerzero|zksync|starknet|eigenlayer|pump\.?fun|jupiter|raydium|telegram|discord|paypal|apple|microsoft|google|amazon|meta|tesla|spacex|elon)\b/i;
const LURE = /\b(official|support|help ?desk|customer (care|service)|airdrop|claim|giveaway|reward|recovery|refund|validator|presale|whitelist|admin|team|announcement)\b/i;
const num = (s: string | undefined) => (s ? Number(s.replace(/[^\d]/g, '')) || null : null);

export async function inviteCheck(ctx: Ctx, input: string): Promise<ModuleResult<InviteReport>> {
  const raw = input.trim().replace(/^https?:\/\//i, '').replace(/^www\./i, '');
  const tg = /^(?:t(?:elegram)?\.me|telegram\.dog)\/(\+[\w-]+|joinchat\/[\w-]+|s\/[\w]{4,}|[\w]{4,})/i.exec(raw);
  const dc = /^(?:discord\.gg|discord(?:app)?\.com\/invite)\/([\w-]{2,})/i.exec(raw);
  if (!tg && !dc) throw new Error('give a Telegram (t.me/...) or Discord (discord.gg/...) invite link');
  const provenance: Provenance[] = [];
  const reasons: [string, number][] = [];
  let r: Omit<InviteReport, 'verdict' | 'risk' | 'reasons' | 'advice'>;
  if (tg) {
    const path = tg[1]!.replace(/^s\//, '');
    const link = `https://t.me/${path}`;
    const p = await ctx.http.getPage(link, { source: 'telegram-preview', timeoutMs: 20_000, maxBytes: 300_000 });
    provenance.push(p.prov);
    if (!p.data) throw new Error(`t.me did not answer (${p.prov.note ?? p.prov.status})`);
    const h = p.data.body.toString('utf8');
    const meta = (k: string) => new RegExp(`property="og:${k}" content="([^"]*)"`, 'i').exec(h)?.[1]?.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'") ?? null;
    const extra = /tgme_page_extra">([^<]*)</.exec(h)?.[1]?.trim() ?? '';
    const title = meta('title');
    const valid = Boolean(/tgme_page_title/.test(h) && title && !/^Telegram: (Contact|Join Group Chat)/.test(title));
    const kind = /subscriber/i.test(extra) ? 'channel' : /member/i.test(extra) ? 'group' : /tgme_action_button_new[^>]*>\s*(Send Message|Start Bot)/i.test(h) || /@\w+bot\b/i.test(extra) ? 'user or bot' : null;
    r = { link, platform: 'telegram', name: valid ? title : null, description: meta('description'), members: num(/([\d\s]+)\s*(subscribers|members)/i.exec(extra)?.[1]), online: num(/([\d\s]+)\s*online/i.exec(extra)?.[1]), verified: /verified-icon/.test(h), createdAt: null, kind };
    if (!valid) return { module: 'invite', input: link, generatedAt: ctx.now().toISOString(), signals: [], provenance, result: { ...r, verdict: 'invite not valid', risk: 0, reasons: ['the link does not open a group, channel or account: it is expired, private or never existed'], advice: ['Ask for a new link from the project\'s official website.'] } };
    if (/class="[^"]*\b(scam|fake)\b[^"]*"/i.test(h) || /\b(SCAM|FAKE)\b/.test(/tgme_page_title[\s\S]{0,400}/.exec(h)?.[0] ?? '')) reasons.push(['Telegram itself labels this account as scam or fake', 90]);
  } else {
    const code = dc![1]!;
    const link = `https://discord.gg/${code}`;
    const d = await ctx.http.get<{ code?: string; expires_at?: string | null; guild?: { id: string; name: string; description?: string | null; features?: string[]; verification_level?: number; vanity_url_code?: string | null }; approximate_member_count?: number; approximate_presence_count?: number; channel?: { name?: string } }>(`https://discord.com/api/v10/invites/${encodeURIComponent(code)}?with_counts=true&with_expiration=true`, { source: 'discord', ttlSec: 600, retries: 1 });
    provenance.push(d.prov);
    if (!d.data?.guild) return { module: 'invite', input: link, generatedAt: ctx.now().toISOString(), signals: [], provenance, result: { link, platform: 'discord', name: null, description: null, members: null, online: null, verified: false, createdAt: null, kind: null, verdict: 'invite not valid', risk: 0, reasons: [d.prov.note === 'HTTP 404' ? 'the invite is expired or never existed' : `Discord did not answer (${d.prov.note ?? d.prov.status})`], advice: ['Get the invite from the project\'s official website or verified X account.'] } };
    const g = d.data.guild;
    const created = new Date(Number((BigInt(g.id) >> 22n) + 1_420_070_400_000n)).toISOString();
    const feats = g.features ?? [];
    r = { link, platform: 'discord', name: g.name, description: g.description ?? null, members: d.data.approximate_member_count ?? null, online: d.data.approximate_presence_count ?? null, verified: feats.includes('VERIFIED') || feats.includes('PARTNERED'), createdAt: created, kind: feats.includes('COMMUNITY') ? 'community server' : 'server' };
    const age = (ctx.now().getTime() - Date.parse(created)) / 86_400_000;
    if (age < 30) reasons.push([`the server was created ${Math.max(0, Math.round(age))} days ago`, 20]);
    if ((g.verification_level ?? 0) === 0 && (r.members ?? 0) > 50) reasons.push(['no verification level: anyone can post right away, including fake admins', 5]);
    if (d.data.expires_at) reasons.push([`the invite expires on ${d.data.expires_at.slice(0, 10)}: official projects usually share permanent links`, 5]);
  }
  const text = `${r.name ?? ''} ${r.link}`;
  const brand = BRANDS.exec(text)?.[0], lure = LURE.exec(text)?.[0];
  if (!r.verified && brand && lure) reasons.push([`uses "${brand}" and "${lure}" in its name without a verified badge: the classic fake support or fake project pattern`, 50]);
  else if (!r.verified && lure && /support|help|customer|recovery|refund|validator/i.test(lure)) reasons.push([`calls itself "${lure}": real companies do not run support through invite links`, 30]);
  else if (!r.verified && brand && (r.members ?? 0) < 500) reasons.push([`uses the name "${brand}" with only ${r.members ?? 0} members and no verified badge`, 25]);
  if (/airdrop|claim|giveaway|presale|double/i.test(`${r.name ?? ''} ${r.description ?? ''}`)) reasons.push(['promises an airdrop, claim, giveaway or presale', 15]);
  if (r.members !== null && r.online !== null && r.members > 1000 && r.online / r.members < 0.005) reasons.push([`${r.members.toLocaleString('en-US')} members but only ${r.online} online: often bought members`, 10]);

  const risk = Math.min(100, reasons.reduce((s, [, w]) => s + w, 0));
  const verdict: InviteReport['verdict'] = risk >= 90 ? 'labeled scam' : risk >= 50 ? 'likely impersonation' : risk >= 20 ? 'suspicious' : 'no known risk found';
  const advice = risk >= 50
    ? ['Do not join. Nobody from support will ever ask for your seed phrase, a "validation" or a payment in a chat.', 'Find the real community through the project\'s official website.']
    : ['Admins and support never message you first. Ignore anyone in the group who offers help in private messages.'];
  return { module: 'invite', input: r.link, generatedAt: ctx.now().toISOString(), signals: [], provenance, result: { ...r, verdict, risk, reasons: reasons.sort((a, b) => b[1] - a[1]).map(([x]) => x), advice } };
}
