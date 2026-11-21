import { enc, type Ctx } from '../core/context.js';
import type { Sourced } from '../core/types.js';

/** One certificate, reduced to what we need: which hostnames it covers and when it became valid. */
export interface CertEntry {
  names: string[];
  notBefore: string;
  issuer: string;
}

interface CrtShRow {
  name_value: string;
  not_before: string;
  issuer_name: string;
}

/** Certificate Transparency logs via crt.sh (unexpired certs only). */
export async function crtsh(ctx: Ctx, domain: string): Promise<Sourced<CertEntry[]>> {
  const url = `https://crt.sh/?q=${enc(`%.${domain}`)}&output=json&exclude=expired`;
  const r = await ctx.http.get<CrtShRow[]>(url, { source: 'crt.sh', ttlSec: 6 * 3600, timeoutMs: 60_000, retries: 1 });
  const data =
    r.data?.map((row) => ({
      names: row.name_value.split(/\s+/).filter(Boolean),
      notBefore: row.not_before.endsWith('Z') ? row.not_before : `${row.not_before}Z`,
      issuer: /O=([^,]+)/.exec(row.issuer_name)?.[1]?.replace(/"/g, '') ?? row.issuer_name,
    })) ?? null;
  return { data, prov: r.prov };
}

interface CertSpotterRow {
  dns_names?: string[];
  not_before?: string;
  issuer?: { friendly_name?: string; name?: string };
}

/** Fallback CT source. Unauthenticated access returns a limited, oldest-first page, so results are partial. */
export async function certspotter(ctx: Ctx, domain: string): Promise<Sourced<CertEntry[]>> {
  const url = `https://api.certspotter.com/v1/issuances?domain=${enc(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`;
  const r = await ctx.http.get<CertSpotterRow[]>(url, { source: 'certspotter', ttlSec: 6 * 3600, timeoutMs: 30_000, retries: 1 });
  const data =
    r.data?.map((row) => ({
      names: row.dns_names ?? [],
      notBefore: row.not_before ?? '',
      issuer: row.issuer?.friendly_name ?? row.issuer?.name ?? 'unknown',
    })) ?? null;
  return { data, prov: data ? { ...r.prov, note: [r.prov.note, 'partial: unauthenticated first page only'].filter(Boolean).join('; ') } : r.prov };
}
