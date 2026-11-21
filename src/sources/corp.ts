/** Company footprints: hiring (Adzuna), litigation (CourtListener), UK registry (Companies House), brand (Brandfetch). */
import { enc, type Ctx } from '../core/context.js';
import { key, noKey } from '../core/keys.js';
import type { Sourced } from '../core/types.js';

export interface Hiring {
  country: string;
  openings: number;
  sample: { title: string; location: string; created: string; url: string }[];
}

/** Open job ads naming the company, in the US and UK. */
export async function hiring(ctx: Ctx, company: string): Promise<Sourced<Hiring[]>> {
  const id = key('ADZUNA_APP_ID');
  const k = key('ADZUNA_APP_KEY');
  if (!id || !k) return noKey('adzuna', 'ADZUNA_APP_ID and ADZUNA_APP_KEY');
  const results = await Promise.all(
    ['us', 'gb'].map((cc) =>
      ctx.http.get<{ count?: number; results?: { title: string; location?: { display_name?: string }; created: string; redirect_url: string }[] }>(
        `https://api.adzuna.com/v1/api/jobs/${cc}/search/1?app_id=${id}&app_key=${k}&results_per_page=5&sort_by=date&company=${enc(company)}`,
        { source: 'adzuna', ttlSec: 6 * 3600 },
      ),
    ),
  );
  const first = results.find((r) => r.data) ?? results[0]!;
  const data = results.every((r) => !r.data)
    ? null
    : results.map((r, i) => ({
        country: i === 0 ? 'US' : 'GB',
        openings: r.data?.count ?? 0,
        sample: (r.data?.results ?? []).map((j) => ({ title: j.title.replace(/<[^>]+>/g, ''), location: j.location?.display_name ?? '', created: j.created, url: j.redirect_url })),
      }));
  return { data, prov: first.prov };
}

export interface CourtCase {
  name: string;
  filed: string;
  court: string;
  url: string;
}

/** Most recently filed federal dockets mentioning the name. */
export async function courtCases(ctx: Ctx, name: string, max = 10): Promise<Sourced<{ total: number; cases: CourtCase[] }>> {
  const k = key('COURTLISTENER_TOKEN');
  if (!k) return noKey('courtlistener', 'COURTLISTENER_TOKEN');
  const r = await ctx.http.get<{ count?: number; results?: { caseName: string; dateFiled: string; court: string; docket_absolute_url?: string }[] }>(
    `https://www.courtlistener.com/api/rest/v4/search/?q=${enc(`"${name.replace(/"/g, '')}"`)}&type=r&order_by=${enc('dateFiled desc')}`,
    { source: 'courtlistener', ttlSec: 6 * 3600, headers: { authorization: `Token ${k}` } },
  );
  return {
    data: r.data
      ? {
          total: r.data.count ?? 0,
          cases: (r.data.results ?? []).slice(0, max).map((c) => ({ name: c.caseName, filed: c.dateFiled, court: c.court, url: `https://www.courtlistener.com${c.docket_absolute_url ?? ''}` })),
        }
      : null,
    prov: r.prov,
  };
}

export interface UkCompany {
  name: string;
  number: string;
  status: string;
  created: string;
  address: string;
  url: string;
}

export async function ukCompany(ctx: Ctx, name: string): Promise<Sourced<UkCompany>> {
  const k = key('COMPANIES_HOUSE_API_KEY');
  if (!k) return noKey('companies-house', 'COMPANIES_HOUSE_API_KEY');
  const r = await ctx.http.get<{ items?: { title: string; company_number: string; company_status: string; date_of_creation: string; address_snippet: string; links?: { self?: string } }[] }>(
    `https://api.company-information.service.gov.uk/search/companies?q=${enc(name)}&items_per_page=5`,
    { source: 'companies-house', ttlSec: 7 * 86_400, headers: { authorization: `Basic ${Buffer.from(`${k}:`).toString('base64')}` } },
  );
  const q = name.toLowerCase();
  const items = r.data?.items ?? [];
  const best = items.find((i) => i.title.toLowerCase().startsWith(q) && i.company_status === 'active') ?? items.find((i) => i.title.toLowerCase().includes(q));
  return {
    data: best ? { name: best.title, number: best.company_number, status: best.company_status, created: best.date_of_creation, address: best.address_snippet, url: `https://find-and-update.company-information.service.gov.uk${best.links?.self ?? ''}` } : null,
    prov: r.prov,
  };
}

export interface Brand {
  name: string;
  domain: string;
  description: string;
  logo: string | null;
  links: { name: string; url: string }[];
}

export async function brand(ctx: Ctx, domain: string): Promise<Sourced<Brand>> {
  const k = key('BRANDFETCH_API_KEY');
  if (!k) return noKey('brandfetch', 'BRANDFETCH_API_KEY');
  const r = await ctx.http.get<{ name?: string; domain?: string; description?: string; logos?: { formats?: { src: string; format: string }[] }[]; links?: { name: string; url: string }[] }>(
    `https://api.brandfetch.io/v2/brands/${enc(domain)}`,
    { source: 'brandfetch', ttlSec: 30 * 86_400, headers: { authorization: `Bearer ${k}` } },
  );
  const d = r.data;
  return {
    data: d?.name ? { name: d.name, domain: d.domain ?? domain, description: (d.description ?? '').slice(0, 300), logo: d.logos?.[0]?.formats?.find((f) => f.format === 'png' || f.format === 'svg')?.src ?? null, links: d.links ?? [] } : null,
    prov: r.prov,
  };
}
