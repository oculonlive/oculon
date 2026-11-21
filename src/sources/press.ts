/** News and web search: GNews, The Guardian, New York Times, Tavily, Exa, plus Jina/Firecrawl page reading. */
import { DAY_MS, enc, type Ctx } from '../core/context.js';
import { key, noKey } from '../core/keys.js';
import type { Sourced } from '../core/types.js';
import type { NewsItem } from './finance.js';

/** Search options for finding the FIRST coverage of something: oldest first, from a fixed start date. */
export interface EarliestOpts {
  fromIso: string;
}

export async function gnews(ctx: Ctx, q: string, max = 10, earliest?: EarliestOpts): Promise<Sourced<NewsItem[]>> {
  if (earliest) {
    const k = key('GNEWS_API_KEY');
    if (!k) return noKey('gnews', 'GNEWS_API_KEY');
    // GNews has no oldest-first sort; bound the window instead so the earliest stories are inside it.
    const r = await ctx.http.get<{ articles?: { title: string; url: string; publishedAt: string; source?: { name?: string } }[] }>(
      `https://gnews.io/api/v4/search?q=${enc(`"${q.replace(/"/g, '')}"`)}&lang=en&max=${max}&from=${enc(earliest.fromIso.slice(0, 19) + 'Z')}&sortby=publishedAt&apikey=${k}`,
      { source: 'gnews', ttlSec: 6 * 3600 },
    );
    return { data: r.data?.articles?.map((a) => ({ title: a.title, url: a.url, date: a.publishedAt, source: a.source?.name ?? 'gnews' })) ?? null, prov: r.prov };
  }
  const k = key('GNEWS_API_KEY');
  if (!k) return noKey('gnews', 'GNEWS_API_KEY');
  const r = await ctx.http.get<{ articles?: { title: string; url: string; publishedAt: string; source?: { name?: string } }[] }>(
    `https://gnews.io/api/v4/search?q=${enc(`"${q.replace(/"/g, '')}"`)}&lang=en&max=${max}&sortby=publishedAt&apikey=${k}`,
    { source: 'gnews', ttlSec: 3 * 3600 },
  );
  return { data: r.data?.articles?.map((a) => ({ title: a.title, url: a.url, date: a.publishedAt, source: a.source?.name ?? 'gnews' })) ?? null, prov: r.prov };
}

export async function guardian(ctx: Ctx, q: string, days = 14, max = 10, earliest?: EarliestOpts): Promise<Sourced<NewsItem[]>> {
  const k = key('GUARDIAN_API_KEY');
  if (!k) return noKey('guardian', 'GUARDIAN_API_KEY');
  const from = earliest ? earliest.fromIso.slice(0, 10) : new Date(ctx.now().getTime() - days * DAY_MS).toISOString().slice(0, 10);
  const r = await ctx.http.get<{ response?: { results?: { webTitle: string; webUrl: string; webPublicationDate: string }[] } }>(
    `https://content.guardianapis.com/search?q=${enc(`"${q.replace(/"/g, '')}"`)}&from-date=${from}&order-by=${earliest ? 'oldest' : 'newest'}&page-size=${max}&api-key=${k}`,
    { source: 'guardian', ttlSec: 3 * 3600 },
  );
  return { data: r.data?.response?.results?.map((a) => ({ title: a.webTitle, url: a.webUrl, date: a.webPublicationDate, source: 'The Guardian' })) ?? null, prov: r.prov };
}

/** Guardian news stories published on one day (YYYY-MM-DD), in the main news sections. */
export async function guardianDay(ctx: Ctx, date: string, max = 30): Promise<Sourced<NewsItem[]>> {
  const k = key('GUARDIAN_API_KEY');
  if (!k) return noKey('guardian', 'GUARDIAN_API_KEY');
  const sections = 'world|us-news|uk-news|business|technology|politics|environment|science';
  const r = await ctx.http.get<{ response?: { results?: { webTitle: string; webUrl: string; webPublicationDate: string }[] } }>(
    `https://content.guardianapis.com/search?from-date=${date}&to-date=${date}&section=${enc(sections)}&order-by=newest&page-size=${max}&api-key=${k}`,
    { source: 'guardian', ttlSec: 30 * 86_400 },
  );
  return { data: r.data?.response?.results?.map((a) => ({ title: a.webTitle, url: a.webUrl, date: a.webPublicationDate, source: 'The Guardian' })) ?? null, prov: r.prov };
}

/** Number of Guardian articles matching `q` between two dates (YYYY-MM-DD, inclusive). */
export async function guardianCount(ctx: Ctx, q: string, from: string, to: string): Promise<Sourced<number>> {
  const k = key('GUARDIAN_API_KEY');
  if (!k) return noKey('guardian', 'GUARDIAN_API_KEY');
  const r = await ctx.http.get<{ response?: { total?: number } }>(
    `https://content.guardianapis.com/search?q=${enc(`"${q.replace(/"/g, '')}"`)}&from-date=${from}&to-date=${to}&page-size=1&api-key=${k}`,
    { source: 'guardian', ttlSec: 12 * 3600 },
  );
  return { data: r.data?.response?.total ?? null, prov: r.prov };
}

export async function nytSearch(ctx: Ctx, q: string, days = 14, earliest?: EarliestOpts): Promise<Sourced<NewsItem[]>> {
  const k = key('NYT_API_KEY');
  if (!k) return noKey('nyt', 'NYT_API_KEY');
  const begin = (earliest ? earliest.fromIso : new Date(ctx.now().getTime() - days * DAY_MS).toISOString()).slice(0, 10).replace(/-/g, '');
  const r = await ctx.http.get<{ response?: { docs?: { headline?: { main?: string }; web_url: string; pub_date: string }[] | null } }>(
    `https://api.nytimes.com/svc/search/v2/articlesearch.json?q=${enc(q)}&begin_date=${begin}&sort=${earliest ? 'oldest' : 'newest'}&api-key=${k}`,
    { source: 'nyt', ttlSec: 3 * 3600 },
  );
  return { data: r.data?.response ? (r.data.response.docs ?? []).map((d) => ({ title: d.headline?.main ?? '', url: d.web_url, date: d.pub_date, source: 'New York Times' })) : null, prov: r.prov };
}

export async function nytTopStories(ctx: Ctx): Promise<Sourced<NewsItem[]>> {
  const k = key('NYT_API_KEY');
  if (!k) return noKey('nyt', 'NYT_API_KEY');
  const r = await ctx.http.get<{ results?: { title: string; url: string; published_date: string; section: string }[] }>(`https://api.nytimes.com/svc/topstories/v2/home.json?api-key=${k}`, {
    source: 'nyt',
    ttlSec: 1800,
  });
  return { data: r.data?.results?.filter((s) => s.title).map((s) => ({ title: s.title, url: s.url, date: s.published_date, source: `NYT ${s.section}` })) ?? null, prov: r.prov };
}

export interface WebResult {
  title: string;
  url: string;
  snippet: string;
  date: string | null;
}

/** Web search: Tavily first, Exa as fallback. */
export async function webSearch(ctx: Ctx, q: string, max = 6, news = false): Promise<Sourced<WebResult[]>> {
  const tv = key('TAVILY_API_KEY');
  if (tv) {
    const r = await postJson<{ results?: { title: string; url: string; content: string; published_date?: string }[] }>(
      ctx,
      'https://api.tavily.com/search',
      { query: q, max_results: max, ...(news ? { topic: 'news', days: 7 } : {}) },
      { authorization: `Bearer ${tv}` },
      'tavily',
    );
    if (r.data) return { data: r.data.results?.map((x) => ({ title: x.title, url: x.url, snippet: x.content.slice(0, 300), date: x.published_date ?? null })) ?? [], prov: r.prov };
  }
  const ex = key('EXA_API_KEY');
  if (!ex) return noKey('websearch', 'TAVILY_API_KEY or EXA_API_KEY');
  const r = await postJson<{ results?: { title: string; url: string; text?: string; publishedDate?: string }[] }>(
    ctx,
    'https://api.exa.ai/search',
    { query: q, numResults: max, contents: { text: { maxCharacters: 300 } } },
    { 'x-api-key': ex },
    'exa',
  );
  return { data: r.data?.results?.map((x) => ({ title: x.title, url: x.url, snippet: (x.text ?? '').slice(0, 300), date: x.publishedDate ?? null })) ?? null, prov: r.prov };
}

/** Readable text of a web page: Jina Reader first, Firecrawl as fallback. Capped at `maxChars`. */
export async function readPage(ctx: Ctx, url: string, maxChars = 6000): Promise<Sourced<string>> {
  if (!/^https?:\/\//i.test(url)) return { data: null, prov: { source: 'reader', url, status: 'ERROR', fetchedAt: new Date().toISOString(), note: 'only http(s) URLs' } };
  const jina = key('JINA_API_KEY');
  const r = await ctx.http.get<string>(`https://r.jina.ai/${url}`, { source: 'jina', as: 'text', ttlSec: 6 * 3600, timeoutMs: 45_000, ...(jina ? { headers: { authorization: `Bearer ${jina}` } } : {}) });
  if (r.data) return { data: r.data.slice(0, maxChars), prov: r.prov };
  const fc = key('FIRECRAWL_API_KEY');
  if (!fc) return r;
  const f = await postJson<{ data?: { markdown?: string } }>(ctx, 'https://api.firecrawl.dev/v1/scrape', { url, formats: ['markdown'], onlyMainContent: true }, { authorization: `Bearer ${fc}` }, 'firecrawl');
  return { data: f.data?.data?.markdown?.slice(0, maxChars) ?? null, prov: f.prov };
}

/**
 * POST JSON with caching keyed on the body. Used for search APIs whose results are fine to reuse for a few hours.
 */
export async function postJson<T>(ctx: Ctx, url: string, body: unknown, headers: Record<string, string>, source: string, ttlSec = 3 * 3600): Promise<Sourced<T>> {
  const cacheKey = `post:${url}:${JSON.stringify(body)}`;
  const cached = ctx.store.cacheGet(cacheKey);
  if (cached && Date.now() - cached.fetchedAt < ttlSec * 1000) {
    return { data: JSON.parse(cached.body) as T, prov: { source, url, status: 'CACHED', fetchedAt: new Date(cached.fetchedAt).toISOString() } };
  }
  const r = await ctx.http.postBytes(url, new TextEncoder().encode(JSON.stringify(body)), { source, headers: { 'content-type': 'application/json', ...headers }, timeoutMs: 45_000 });
  if (!r.data) return { data: null, prov: r.prov };
  try {
    const text = r.data.toString('utf8');
    const data = JSON.parse(text) as T;
    ctx.store.cachePut(cacheKey, text);
    return { data, prov: r.prov };
  } catch {
    return { data: null, prov: { ...r.prov, status: 'ERROR', note: 'invalid JSON' } };
  }
}
