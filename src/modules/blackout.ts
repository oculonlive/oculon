/**
 * Blackout radar: countries and networks whose internet traffic suddenly dropped.
 *   Cloudflare Radar (token): outages its analysts confirmed, with cause, plus automatic traffic anomalies.
 *   IODA (Georgia Tech, no key): outage scores per country from BGP routing, active probing and Google traffic.
 * Shutdowns ordered by governments, power cuts, cable cuts and disasters all show up here, often before news.
 * Signals come only from Cloudflare-confirmed outages and verified location anomalies; IODA corroborates.
 */
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { countryRouting } from './bgp.js';

export interface Outage {
  source: 'cloudflare' | 'cloudflare-anomaly';
  country: string | null;
  countryCode: string | null;
  network: string | null;
  start: string;
  end: string | null;
  cause: string | null;
  type: string | null;
  description: string;
  url: string | null;
  verified: boolean;
}

export interface IodaCountry {
  code: string;
  name: string;
  score: number;
  events: number;
}

export interface Blackout {
  days: number;
  outages: Outage[];
  ioda: IodaCountry[];
  /** RIPEstat: visible IPv4 prefixes now versus the window's median, for countries with a confirmed outage. */
  routing: { country: string; v4Now: number; v4Baseline: number; change: number }[];
}

const CF = 'https://api.cloudflare.com/client/v4/radar';

export async function blackout(ctx: Ctx, days = 2): Promise<ModuleResult<Blackout>> {
  const now = ctx.now();
  const provenance: Provenance[] = [];
  const outages: Outage[] = [];
  const range = days <= 1 ? '1d' : days <= 2 ? '2d' : days <= 7 ? '7d' : '14d';
  const token = key('CLOUDFLARE_API_TOKEN');
  if (token) {
    const auth = { authorization: `Bearer ${token}` };
    const [ann, anom] = await Promise.all([
      ctx.http.get<{ result?: { annotations?: { description?: string; startDate: string; endDate?: string | null; linkedUrl?: string; outage?: { outageCause?: string; outageType?: string }; asnsDetails?: { asn: string; name: string; location?: { code: string; name: string } }[]; locationsDetails?: { code: string; name: string }[] }[] } }>(
        `${CF}/annotations/outages?dateRange=${range}&limit=50&format=json`,
        { source: 'cloudflare-radar', ttlSec: 900, headers: auth },
      ),
      ctx.http.get<{ result?: { trafficAnomalies?: { status: string; type: string; startDate: string; endDate?: string | null; locationDetails?: { code: string; name: string } | null; asnDetails?: { asn: string; name: string; location?: { code: string; name: string } } | null; outageId?: string | null }[] } }>(
        `${CF}/traffic_anomalies?dateRange=${range}&limit=50&format=json`,
        { source: 'cloudflare-radar', ttlSec: 900, headers: auth },
      ),
    ]);
    provenance.push(ann.prov, anom.prov);
    for (const a of ann.data?.result?.annotations ?? []) {
      const loc = a.locationsDetails?.[0] ?? a.asnsDetails?.[0]?.location ?? null;
      outages.push({
        source: 'cloudflare',
        country: loc?.name ?? null,
        countryCode: loc?.code ?? null,
        network: a.asnsDetails?.length ? a.asnsDetails.map((x) => `${x.name} (AS${x.asn})`).join(', ') : null,
        start: a.startDate,
        end: a.endDate ?? null,
        cause: a.outage?.outageCause && a.outage.outageCause !== 'UNKNOWN' ? a.outage.outageCause.toLowerCase().replace(/_/g, ' ') : null,
        type: a.outage?.outageType?.toLowerCase() ?? null,
        description: a.description ?? 'Internet disruption',
        url: a.linkedUrl ?? 'https://radar.cloudflare.com/outage-center',
        verified: true,
      });
    }
    // Anomalies already explained by an annotation are not repeated.
    for (const x of anom.data?.result?.trafficAnomalies ?? []) {
      if (x.outageId) continue;
      const loc = x.locationDetails ?? x.asnDetails?.location ?? null;
      outages.push({
        source: 'cloudflare-anomaly',
        country: loc?.name ?? null,
        countryCode: loc?.code ?? null,
        network: x.asnDetails ? `${x.asnDetails.name} (AS${x.asnDetails.asn})` : null,
        start: x.startDate,
        end: x.endDate ?? null,
        cause: null,
        type: x.type.toLowerCase(),
        description: `Traffic anomaly ${x.asnDetails ? `on ${x.asnDetails.name}` : ''}${loc ? ` in ${loc.name}` : ''}`.replace(/\s+/g, ' ').trim(),
        url: loc ? `https://radar.cloudflare.com/traffic/${loc.code.toLowerCase()}` : 'https://radar.cloudflare.com',
        verified: x.status === 'VERIFIED',
      });
    }
  } else {
    provenance.push({ source: 'cloudflare-radar', url: CF, status: 'UNAVAILABLE', fetchedAt: now.toISOString(), note: 'set CLOUDFLARE_API_TOKEN (free, "Read Cloudflare Radar data")' });
  }

  const until = Math.floor(now.getTime() / 1000);
  const io = await ctx.http.get<{ data?: { scores?: { overall?: number }; event_cnt?: number; entity?: { code: string; name: string } }[] }>(
    `https://api.ioda.inetintel.cc.gatech.edu/v2/outages/summary?from=${until - days * 86_400}&until=${until}&entityType=country&limit=15`,
    { source: 'ioda', ttlSec: 900, timeoutMs: 45_000 },
  );
  provenance.push(io.prov);
  const ioda = (io.data?.data ?? []).filter((d) => d.entity).map((d) => ({ code: d.entity!.code, name: d.entity!.name, score: Math.round(d.scores?.overall ?? 0), events: d.event_cnt ?? 0 }));

  outages.sort((a, b) => b.start.localeCompare(a.start));
  // Routing evidence for up to 4 countries with a confirmed or verified outage (one RIPEstat call each).
  const routing: Blackout['routing'] = [];
  const ccs = [...new Set(outages.filter((o) => o.verified && o.countryCode).map((o) => o.countryCode!))].slice(0, 4);
  for (const cc of ccs) {
    const r = await countryRouting(ctx, cc, Math.max(24, days * 24));
    provenance.push(r.prov);
    if (r.data?.latest && r.data.baseline && r.data.v4Change !== null) routing.push({ country: cc, v4Now: r.data.latest.v4, v4Baseline: r.data.baseline.v4, change: r.data.v4Change });
  }
  const signals: Signal[] = [];
  const iodaCodes = new Set(ioda.slice(0, 10).map((x) => x.code));
  for (const o of outages) {
    if (!o.verified || !o.countryCode) continue;
    if (now.getTime() - Date.parse(o.start) > 48 * 3_600_000) continue;
    const route = routing.find((x) => x.country === o.countryCode);
    const routeDrop = route && route.change <= -0.05 ? route : null;
    const corroborated = iodaCodes.has(o.countryCode) || Boolean(routeDrop);
    const national = !o.network;
    signals.push({
      id: signalId('blackout', o.countryCode, o.network ?? '', o.start.slice(0, 13)),
      module: 'blackout',
      title: `Internet ${national ? 'disruption' : 'outage'} in ${o.country}${o.network ? ` on ${o.network}` : ''}${o.cause ? ` (${o.cause})` : ''}${o.end ? '' : ', ongoing'}`,
      score: Math.min(90, 55 + (national ? 15 : 0) + (corroborated ? 10 : 0) + (o.end ? 0 : 5)),
      evidence: [
        { source: o.source, text: `${o.description} since ${o.start.slice(0, 16).replace('T', ' ')} UTC${o.end ? `, until ${o.end.slice(0, 16).replace('T', ' ')} UTC` : ''}`, ...(o.url ? { url: o.url } : {}) },
        ...(iodaCodes.has(o.countryCode) ? [{ source: 'ioda', text: `IODA also ranks ${o.country} among the top countries by outage score in the window`, url: `https://ioda.inetintel.cc.gatech.edu/country/${o.countryCode}` }] : []),
        ...(routeDrop ? [{ source: 'ripestat', text: `${Math.round(-routeDrop.change * 100)}% fewer IPv4 prefixes visible in global routing (${routeDrop.v4Now} vs ${routeDrop.v4Baseline})`, url: `https://stat.ripe.net/${o.countryCode}` }] : []),
      ],
      createdAt: now.toISOString(),
    });
  }
  for (const s of signals) ctx.graph.saveSignal(s);
  return { module: 'blackout', input: `${days}d`, generatedAt: now.toISOString(), result: { days, outages, ioda, routing }, signals, provenance };
}
