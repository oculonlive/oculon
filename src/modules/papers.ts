/**
 * Research brief: what the literature says about a topic.
 *   OpenAlex (no key; OPENALEX_API_KEY raises the budget): the most cited recent papers, the newest relevant
 *     ones, and papers per year to show whether the field is growing.
 *   PubMed (no key): recent biomedical papers when the topic is medical.
 *   Semantic Scholar (SEMANTIC_SCHOLAR_API_KEY, optional): one-line TLDRs for the top papers.
 *   An LLM writes a short overview that cites the numbered papers; without one, the list stands alone.
 */
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import { complete } from '../core/llm.js';
import type { ModuleResult, Provenance, Sourced } from '../core/types.js';

export interface Paper {
  n: number;
  title: string;
  year: number | null;
  date: string | null;
  authors: string[];
  venue: string | null;
  citations: number;
  url: string;
  openAccessUrl: string | null;
  abstract: string;
  tldr: string | null;
  source: 'openalex' | 'pubmed';
}

export interface PapersResult {
  topic: string;
  totalWorks: number | null;
  perYear: { year: number; count: number }[];
  trend: 'growing' | 'steady' | 'shrinking' | null;
  mostCited: Paper[];
  newest: Paper[];
  pubmed: { count: number; papers: Paper[] } | null;
  overview: string | null;
  method: string;
}

interface OaWork { id?: string; title?: string; display_name?: string; publication_year?: number; publication_date?: string; cited_by_count?: number; doi?: string | null; open_access?: { oa_url?: string | null }; primary_location?: { source?: { display_name?: string } | null } | null; authorships?: { author?: { display_name?: string } }[]; abstract_inverted_index?: Record<string, number[]> | null }

/** OpenAlex stores abstracts as word → positions; this puts the words back in order. */
export function invertAbstract(idx: Record<string, number[]> | null | undefined, max = 600): string {
  if (!idx) return '';
  const words: string[] = [];
  for (const [w, ps] of Object.entries(idx)) for (const p of ps) words[p] = w;
  return words.filter(Boolean).join(' ').slice(0, max);
}

const OA = 'https://api.openalex.org/works';
const SELECT = 'id,title,display_name,publication_year,publication_date,cited_by_count,doi,open_access,primary_location,authorships,abstract_inverted_index';
const oaKey = () => { const k = key('OPENALEX_API_KEY'); return k ? `&api_key=${encodeURIComponent(k)}` : ''; };

const toPaper = (w: OaWork): Omit<Paper, 'n'> => ({
  title: (w.title ?? w.display_name ?? '').replace(/<[^>]+>/g, '').trim(),
  year: w.publication_year ?? null,
  date: w.publication_date ?? null,
  authors: (w.authorships ?? []).slice(0, 4).map((a) => a.author?.display_name ?? '').filter(Boolean),
  venue: w.primary_location?.source?.display_name ?? null,
  citations: w.cited_by_count ?? 0,
  url: w.doi ?? w.id ?? '',
  openAccessUrl: w.open_access?.oa_url ?? null,
  abstract: invertAbstract(w.abstract_inverted_index),
  tldr: null,
  source: 'openalex',
});

async function oaSearch(ctx: Ctx, topic: string, extra: string): Promise<Sourced<{ count: number; works: OaWork[] }>> {
  const r = await ctx.http.get<{ count: number; works: OaWork[] }>(`${OA}?search=${encodeURIComponent(topic)}&${extra}&select=${SELECT}${oaKey()}`, {
    source: 'openalex',
    ttlSec: 12 * 3600,
    keep: (d: { meta?: { count?: number }; results?: OaWork[] }) => ({ count: d.meta?.count ?? 0, works: d.results ?? [] }),
  });
  return { data: r.data, prov: { ...r.prov, url: r.prov.url.replace(/&api_key=[^&]+/, '') } };
}

async function perYear(ctx: Ctx, topic: string, fromYear: number): Promise<Sourced<{ year: number; count: number }[]>> {
  const r = await ctx.http.get<{ year: number; count: number }[]>(`${OA}?search=${encodeURIComponent(topic)}&filter=from_publication_date:${fromYear}-01-01&group_by=publication_year${oaKey()}`, {
    source: 'openalex',
    ttlSec: 24 * 3600,
    keep: (d: { group_by?: { key: string; count: number }[] }) => (d.group_by ?? []).map((g) => ({ year: Number(g.key), count: g.count })).sort((a, b) => a.year - b.year),
  });
  return { data: r.data, prov: { ...r.prov, url: r.prov.url.replace(/&api_key=[^&]+/, '') } };
}

const MEDICAL = /\b(disease|cancer|drug|therapy|treatment|vaccine|clinical|patient|virus|viral|infection|diabetes|obesity|glp-?1|alzheimer|covid|syndrome|tumou?r|gene|protein|antibod|medic|health|surgery|cardio|heart|brain|mental|depress|antibiotic|microbiome|trial)\b/i;

async function pubmed(ctx: Ctx, topic: string): Promise<{ data: PapersResult['pubmed']; prov: Provenance[] }> {
  const E = 'https://eutils.ncbi.nlm.nih.gov/entrez/eutils';
  const s = await ctx.http.get<{ count: number; ids: string[] }>(`${E}/esearch.fcgi?db=pubmed&term=${encodeURIComponent(topic)}&retmode=json&retmax=6&sort=relevance&datetype=pdat&reldate=730`, { source: 'pubmed', ttlSec: 12 * 3600, keep: (d: { esearchresult?: { count?: string; idlist?: string[] } }) => ({ count: Number(d.esearchresult?.count ?? 0), ids: d.esearchresult?.idlist ?? [] }) });
  if (!s.data?.ids.length) return { data: s.data ? { count: s.data.count, papers: [] } : null, prov: [s.prov] };
  type Sum = { uid: string; title?: string; pubdate?: string; fulljournalname?: string; authors?: { name: string }[] };
  const m = await ctx.http.get<Sum[]>(`${E}/esummary.fcgi?db=pubmed&id=${s.data.ids.join(',')}&retmode=json`, { source: 'pubmed', ttlSec: 24 * 3600, keep: (d: { result?: Record<string, Sum> & { uids?: string[] } }) => (d.result?.uids ?? []).map((u) => d.result![u] as Sum) });
  const papers = (m.data ?? []).map((x) => ({ n: 0, title: (x.title ?? '').replace(/<[^>]+>/g, ''), year: Number(/\d{4}/.exec(x.pubdate ?? '')?.[0]) || null, date: x.pubdate ?? null, authors: (x.authors ?? []).slice(0, 4).map((a) => a.name), venue: x.fulljournalname ?? null, citations: 0, url: `https://pubmed.ncbi.nlm.nih.gov/${x.uid}/`, openAccessUrl: null, abstract: '', tldr: null, source: 'pubmed' as const }));
  return { data: { count: s.data.count, papers }, prov: [s.prov, m.prov] };
}

async function tldrs(ctx: Ctx, papers: Paper[]): Promise<Provenance | null> {
  const k = key('SEMANTIC_SCHOLAR_API_KEY');
  const dois = papers.filter((p) => /doi\.org\//.test(p.url)).slice(0, 20);
  if (!k || !dois.length) return null;
  const ids = dois.map((p) => `DOI:${p.url.replace(/^https?:\/\/doi\.org\//, '')}`);
  const cacheKey = `post:s2-batch:${ids.join(',')}`;
  const cached = ctx.store.cacheGet(cacheKey);
  let rows: ({ tldr?: { text?: string } } | null)[] | null = null;
  if (cached && Date.now() - cached.fetchedAt < 7 * 86_400_000) rows = JSON.parse(cached.body);
  else {
    const r = await ctx.http.postBytes('https://api.semanticscholar.org/graph/v1/paper/batch?fields=tldr', new TextEncoder().encode(JSON.stringify({ ids })), { source: 'semantic-scholar', headers: { 'content-type': 'application/json', 'x-api-key': k }, timeoutMs: 20_000 });
    if (!r.data) return r.prov;
    try { rows = JSON.parse(r.data.toString('utf8')); ctx.store.cachePut(cacheKey, r.data.toString('utf8')); } catch { return { ...r.prov, status: 'ERROR', note: 'invalid JSON' }; }
  }
  rows?.forEach((row, i) => { if (row?.tldr?.text) dois[i]!.tldr = row.tldr.text; });
  return { source: 'semantic-scholar', url: 'https://api.semanticscholar.org/graph/v1/paper/batch', status: cached ? 'CACHED' : 'LIVE', fetchedAt: new Date().toISOString() };
}

export async function papers(ctx: Ctx, topicInput: string, opts: { years?: number } = {}): Promise<ModuleResult<PapersResult>> {
  const topic = topicInput.trim();
  if (topic.length < 2) throw new Error('missing topic');
  const years = Math.max(1, Math.min(opts.years ?? 3, 15));
  const nowYear = ctx.now().getUTCFullYear();
  const from = `${nowYear - years}-01-01`;
  const provenance: Provenance[] = [];
  const [cited, fresh, py, pm] = await Promise.all([
    // Most relevant 25 first, then the most cited of those: sorting the whole match set by citations pulls in
    // famous papers that only mention the words.
    oaSearch(ctx, topic, `filter=from_publication_date:${from},type:article|review|preprint&sort=relevance_score:desc&per-page=25`),
    oaSearch(ctx, topic, `filter=from_publication_date:${new Date(ctx.now().getTime() - 180 * 86_400_000).toISOString().slice(0, 10)},type:article|review|preprint&sort=relevance_score:desc&per-page=6`),
    perYear(ctx, topic, nowYear - 6),
    MEDICAL.test(topic) ? pubmed(ctx, topic) : Promise.resolve(null),
  ]);
  provenance.push(cited.prov, fresh.prov, py.prov, ...(pm?.prov ?? []));
  let n = 0;
  const mostCited: Paper[] = [...(cited.data?.works ?? [])].sort((a, b) => (b.cited_by_count ?? 0) - (a.cited_by_count ?? 0)).slice(0, 8).map((w) => ({ ...toPaper(w), n: ++n })).filter((p) => p.title);
  const seen = new Set(mostCited.map((p) => p.title.toLowerCase()));
  const newest: Paper[] = (fresh.data?.works ?? []).map(toPaper).filter((p) => p.title && !seen.has(p.title.toLowerCase())).map((p) => ({ ...p, n: ++n }));
  const pubmedPapers = pm?.data ? { count: pm.data.count, papers: pm.data.papers.map((p) => ({ ...p, n: ++n })) } : null;
  const s2 = await tldrs(ctx, [...mostCited, ...newest]);
  if (s2) provenance.push(s2);

  // Growth: the last full year against the average of the three before it.
  const years6 = (py.data ?? []).filter((x) => x.year < nowYear);
  const last = years6.at(-1)?.count ?? 0;
  const prior = years6.slice(-4, -1).map((x) => x.count);
  const avg = prior.length ? prior.reduce((a, b) => a + b, 0) / prior.length : 0;
  const trend = !avg || !last ? null : last > avg * 1.2 ? 'growing' : last < avg * 0.8 ? 'shrinking' : 'steady';

  let overview: string | null = null;
  let method = 'OpenAlex ranking';
  const all = [...mostCited, ...newest, ...(pubmedPapers?.papers ?? [])];
  if (all.length) {
    try {
      const list = all.slice(0, 16).map((p) => `[${p.n}] ${p.title} (${p.year ?? '?'}, ${p.venue ?? 'unknown venue'}, ${p.citations} citations)${p.tldr ? ` TLDR: ${p.tldr}` : p.abstract ? ` Abstract: ${p.abstract.slice(0, 350)}` : ''}`).join('\n');
      const x = await complete(
        'You summarize research for a busy reader. Using ONLY the numbered papers, write 3-5 sentences on what the recent literature on the topic finds and where it is heading. Cite papers like [3]. No claims beyond the papers. Plain English.',
        `Topic: ${topic}\n\n${list}`,
        { maxTokens: 350, temperature: 0.2 },
      );
      overview = x.text.slice(0, 1500) || null;
      method = `${x.provider} over ${Math.min(all.length, 16)} papers`;
    } catch {
      // no LLM: the ranked lists stand alone
    }
  }
  return {
    module: 'papers',
    input: topic,
    generatedAt: ctx.now().toISOString(),
    result: { topic, totalWorks: cited.data?.count ?? null, perYear: py.data ?? [], trend, mostCited, newest, pubmed: pubmedPapers, overview, method },
    signals: [],
    provenance,
  };
}
