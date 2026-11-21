/**
 * Daily request budgets for free-tier APIs. Counted per source per UTC day in the database, so a busy
 * dashboard or watch loop cannot burn a whole month's free quota. Cached responses do not count.
 * Budgets sit a little under each provider's published free limit; override with OCULON_QUOTA_<SOURCE>=n.
 */
import type { Store } from './store.js';

export const DAILY_BUDGET: Record<string, number> = {
  gnews: 90, // 100/day free
  nyt: 450, // 500/day
  guardian: 450, // 500/day developer key
  youtube: 90, // search costs 100 of 10,000 daily units
  tavily: 30, // 1,000/month
  exa: 30, // 1,000/month
  firecrawl: 15, // 500 credits one-off / month
  jina: 300,
  finnhub: 3000,
  adzuna: 230, // 250/day
  courtlistener: 4000,
  'companies-house': 5000,
  brandfetch: 90,
  urlscan: 900,
  'safe-browsing': 9000,
  zerion: 2000,
  etherscan: 90_000,
  webacy: 900,
  openaq: 2000,
  openalex: 9000,
  bluesky: 2000,
  coingecko: 300, // demo: 10,000/month
  fred: 2000,
  'github-search': 1000,
  geckoterminal: 2500,
  kalshi: 2000,
  manifold: 2000,
  itunes: 1000,
  huggingface: 3000,
  npm: 5000,
  wikidata: 2000,
  ofac: 50,
  blockscout: 20000,
  gfw: 2000,
  ripestat: 2000,
  statuspage: 20000,
  opensanctions: 300,
  firms: 2000, // 5,000 transactions per 10 minutes
  copernicus: 300, // free account: processing units are monthly, keep requests modest
  'cloudflare-radar': 5000,
  ioda: 2000,
  gdacs: 2000,
  'cisa-kev': 10, // 1.9 MB catalog, cached 6h
  nvd: 150, // keyless: 5 requests per 30 s
  epss: 300,
  osv: 500,
  'github-advisories': 50, // shares GitHub's 60/hour keyless limit
  'federal-register': 300,
  defillama: 500,
  'defillama-stablecoins': 200,
  'defillama-yields': 50, // ~10 MB per call
  'alternative-me': 100,
  openchain: 1000,
  '4byte': 500,
  'nasa-donki': 900, // 1,000/hour with a key; DEMO_KEY is 50/day
  'nasa-neows': 500,
  openfda: 900, // 1,000/day per IP without a key
  clinicaltrials: 2000,
  gdelt: 2000,
  // Paid, pay-per-use: kept small on purpose. Raise with OCULON_QUOTA_ANTHROPIC / OCULON_QUOTA_APIFY.
  anthropic: 150,
  apify: 40,
  deepgram: 30, // transcriptions per day
  'shodan-internetdb': 2000,
};

const envName = (source: string) => `OCULON_QUOTA_${source.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;

export function budgetFor(source: string): number | null {
  const override = Number(process.env[envName(source)]);
  if (Number.isFinite(override) && override > 0) return override;
  return DAILY_BUDGET[source] ?? null;
}

const today = () => new Date().toISOString().slice(0, 10);

/** Reserve one request; returns false when today's budget for the source is spent. */
export function takeQuota(store: Store, source: string): boolean {
  const budget = budgetFor(source);
  if (budget === null) return true;
  const day = today();
  const row = store.db.prepare('SELECT used FROM quota WHERE source = ? AND day = ?').get(source, day) as { used: number } | undefined;
  if ((row?.used ?? 0) >= budget) return false;
  store.db.prepare('INSERT INTO quota (source, day, used) VALUES (?, ?, 1) ON CONFLICT(source, day) DO UPDATE SET used = used + 1').run(source, day);
  return true;
}

export function quotaUsage(store: Store, day = today()): { source: string; used: number; budget: number | null }[] {
  const rows = store.db.prepare('SELECT source, used FROM quota WHERE day = ? ORDER BY used DESC').all(day) as { source: string; used: number }[];
  return rows.map((r) => ({ ...r, budget: budgetFor(r.source) }));
}
