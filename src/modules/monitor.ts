/**
 * Monitors in plain language: "tell me when there is an internet outage in Iran", "watch new critical CVEs for
 * nginx", "alert me about earthquakes above 6 near Tokyo". A sentence becomes one watchlist rule (kind + target)
 * that Meerkat re-checks on the shared schedule and reports only when something changes, with evidence.
 * An LLM reads the sentence; without one, a small set of patterns covers the common phrasings.
 */
import type { Ctx } from '../core/context.js';
import { complete } from '../core/llm.js';
import { addWatch, WATCH_KINDS, type WatchItem, type WatchKind } from './meerkat.js';
import { onchainEnabled, ONCHAIN_WATCH_KINDS } from '../core/features.js';

export interface MonitorRule {
  kind: WatchKind;
  target: string;
  /** What the rule does, in one line, for lists and alerts. */
  description: string;
}

const KIND_HELP: Record<WatchKind, string> = {
  news: 'new news stories about a keyword or name. target: the keyword',
  outage: 'internet outages in a country. target: country name or 2-letter code',
  cve: 'newly exploited (CISA KEV) or new critical vulnerabilities for a vendor or product. target: vendor or product, e.g. "nginx", "Microsoft Exchange"',
  quake: 'earthquakes within 300 km of a place. target: "place|minimum magnitude", e.g. "Tokyo|6"',
  hazard: 'orange or red disaster alerts (cyclones, floods, volcanoes, quakes, wildfires) for a country or named storm. target: country or name',
  url: 'a link turning malicious or suspicious. target: the URL',
  package: 'new vulnerabilities, deprecation or releases of a software package. target: "npm:name" or "pypi:name"',
  travel: 'travel risk level changes for a destination. target: city or country',
  company: 'news, court cases, stock moves, insider sales and hiring for a company. target: company name or ticker',
  domain: 'new subdomains, archived pages and Safe Browsing flags for a domain. target: the domain',
  plane: 'a specific aircraft taking off, landing or changing status. target: tail number, callsign or ICAO hex',
  topic: 'hype phase changes for a topic. target: the topic',
  lights: 'night-time light changes (blackouts, growth) for a place. target: the place',
  air: 'air quality category changes for a place. target: the place',
  port: 'ships queuing or military vessels at a port. target: the port',
  wallet: 'activity of a crypto wallet. target: the address',
  token: 'risk verdict and liquidity of a token. target: the contract address',
};

export const availableKinds = (): WatchKind[] => WATCH_KINDS.filter((k) => onchainEnabled() || !ONCHAIN_WATCH_KINDS.has(k));

const describe = (kind: WatchKind, target: string): string => {
  switch (kind) {
    case 'news': return `new stories about "${target}"`;
    case 'outage': return `internet outages in ${target}`;
    case 'cve': return `exploited or critical vulnerabilities for ${target}`;
    case 'quake': { const [p, m] = target.split('|'); return `earthquakes M${m ?? '5'}+ within 300 km of ${p}`; }
    case 'hazard': return `orange or red disaster alerts for ${target}`;
    case 'url': return `${target} turning malicious or suspicious`;
    case 'package': return `new advisories, deprecation or releases of ${target}`;
    case 'travel': return `travel risk changes for ${target}`;
    case 'company': return `news, filings, cases and stock moves for ${target}`;
    case 'domain': return `new footprints of ${target}`;
    case 'plane': return `status changes of aircraft ${target}`;
    case 'topic': return `hype phase changes for ${target}`;
    case 'lights': return `night-light changes in ${target}`;
    case 'air': return `air quality changes in ${target}`;
    case 'port': return `vessel queues at ${target}`;
    case 'wallet': return `activity of wallet ${target}`;
    case 'token': return `risk changes of token ${target}`;
  }
};

// Drops quotes, a leading "the", and trailing verbs such as "changes", "gets worse", "turns red".
const clean = (s: string) =>
  s.trim().replace(/^["'“”]+|["'“”.!?]+$/g, '').replace(/^the\s+/i, '').replace(/\s+(changes?|gets?|goes|turns?|becomes?|is|are|has|have|worsens?|improves?)\b.*$/i, '').trim();

/** Pattern fallback for the common phrasings (used when no LLM is configured or it gives an unusable answer). */
export function parseMonitorPattern(text: string): MonitorRule | null {
  // "the Philippines" → "Philippines", so place patterns can start at the capitalized name.
  const t = text.trim().replace(/\bthe\s+(?=[A-Z])/g, '');
  const after = (re: RegExp) => { const m = re.exec(t); return m?.[1] ? clean(m[1]) : null; };
  let target: string | null;
  if ((target = after(/\b(https?:\/\/\S+)/i))) return { kind: 'url', target, description: describe('url', target) };
  if ((target = after(/\b((?:npm|pypi):[@\w./-]+)/i))) return { kind: 'package', target: target.toLowerCase(), description: describe('package', target.toLowerCase()) };
  if (/\b(outage|blackout|shutdown|internet (?:is )?down|goes offline|disconnect)/i.test(t) && (target = after(/\b(?:in|for|across)\s+([A-Z][\w .'-]+?)(?:\s*$|[,.!?]|\s+(?:and|or|when|if)\b)/))) return { kind: 'outage', target, description: describe('outage', target) };
  if (/\b(cve|vulnerab|exploit|zero[- ]day|security (?:hole|flaw|bug)|patch)/i.test(t) && (target = after(/\b(?:for|in|affecting|on|about)\s+([\w .+-]+?)(?:\s*$|[,.!?])/i))) return { kind: 'cve', target, description: describe('cve', target) };
  if (/\b(earthquake|quake|tremor|seismic)/i.test(t) && (target = after(/\b(?:near|around|in|close to)\s+([A-Z][\w .,'-]+?)(?:\s*$|[.!?]|\s+(?:above|over|of)\b)/))) {
    const mag = /\b(?:above|over|magnitude|m)\s*(\d(?:\.\d)?)/i.exec(t)?.[1] ?? /(\d(?:\.\d)?)\s*\+/.exec(t)?.[1];
    const tg = `${target}|${mag ?? '5'}`;
    return { kind: 'quake', target: tg, description: describe('quake', tg) };
  }
  if (/\b(cyclone|hurricane|typhoon|flood|volcano|eruption|disaster|wildfire|tsunami|storm)/i.test(t) && (target = after(/\b(?:in|for|near|hitting|affecting)\s+([A-Z][\w .'-]+?)(?:\s*$|[,.!?])/))) return { kind: 'hazard', target, description: describe('hazard', target) };
  if (/\b(travel|trip|safe to (?:go|visit|travel)|visiting|advisory)/i.test(t) && (target = after(/\b(?:to|in|for)\s+([A-Z][\w .'-]+?)(?:\s*$|[,.!?]|\s+(?:next|this|in)\b)/))) return { kind: 'travel', target, description: describe('travel', target) };
  if (/\b(air quality|pollution|smog|pm2\.?5)/i.test(t) && (target = after(/\b(?:in|for|near)\s+([A-Z][\w .'-]+?)(?:\s*$|[,.!?])/))) return { kind: 'air', target, description: describe('air', target) };
  if ((target = after(/\b(?:news|stories|headlines|articles|coverage|mentions?)\s+(?:about|on|of|for|mentioning)\s+(.+?)(?:\s*$|[.!?])/i))) return { kind: 'news', target, description: describe('news', target) };
  return null;
}

/** Reads a sentence into a rule: LLM first (it handles any phrasing), patterns as the fallback. */
export async function parseMonitor(text: string): Promise<MonitorRule & { method: string }> {
  const kinds = availableKinds();
  try {
    const x = await complete(
      `You turn a monitoring request into ONE watch rule for an OSINT engine. Kinds:\n${kinds.map((k) => `- ${k}: ${KIND_HELP[k]}`).join('\n')}\nReply as JSON {"kind": "...", "target": "..."} using exactly one kind from the list. If nothing fits, reply {"kind": "none", "target": ""}.`,
      text,
      { json: true, maxTokens: 80, temperature: 0 },
    );
    const j = JSON.parse(x.text.replace(/^```(json)?|```$/g, '')) as { kind?: string; target?: string };
    const kind = j.kind as WatchKind;
    const target = clean(String(j.target ?? ''));
    if (kinds.includes(kind) && target) {
      const tg = kind === 'quake' && !target.includes('|') ? `${target}|5` : kind === 'package' && !target.includes(':') ? `npm:${target}` : target;
      return { kind, target: tg, description: describe(kind, tg), method: x.provider };
    }
  } catch {
    // fall through to patterns
  }
  const p = parseMonitorPattern(text);
  if (p && kinds.includes(p.kind)) return { ...p, method: 'patterns' };
  throw new Error('could not turn that into a monitor. Try e.g. "internet outages in Iran", "critical CVEs for nginx", "earthquakes above 6 near Tokyo", "news about OpenAI"');
}

/** Parses the sentence and adds the rule to the watchlist (first check records a baseline). */
export async function addMonitor(ctx: Ctx, text: string): Promise<{ item: WatchItem; rule: MonitorRule; method: string }> {
  const r = await parseMonitor(text);
  const item = addWatch(ctx, r.kind, r.target, r.description);
  return { item, rule: { kind: r.kind, target: r.target, description: r.description }, method: r.method };
}
