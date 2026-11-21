/**
 * Hazards: official orange and red disaster alerts from GDACS (the UN / European Commission Global Disaster
 * Alert and Coordination System, no key): earthquakes, tropical cyclones, floods, volcanoes, droughts and
 * wildfires, each with its severity and affected countries. Red alerts and new orange alerts become signals.
 */
import type { Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Signal } from '../core/types.js';

export interface Hazard {
  id: string;
  type: string;
  name: string;
  level: 'Red' | 'Orange' | 'Green';
  countries: string;
  from: string;
  to: string;
  current: boolean;
  severity: string;
  lat: number | null;
  lon: number | null;
  url: string;
}

const TYPES: Record<string, string> = { EQ: 'earthquake', TC: 'tropical cyclone', FL: 'flood', VO: 'volcano', DR: 'drought', WF: 'wildfire' };

export interface Bulletin {
  source: 'NTWC' | 'PTWC' | 'NWS';
  title: string;
  category: string;
  area: string;
  issued: string;
  url: string;
}

const TSUNAMI_FEEDS: [Bulletin['source'], string][] = [
  ['NTWC', 'https://www.tsunami.gov/events/xml/PAAQAtom.xml'],
  ['PTWC', 'https://www.tsunami.gov/events/xml/PHEBAtom.xml'],
];
const NWS_SIGNAL = /^(Tsunami Warning|Hurricane Warning|Typhoon Warning|Extreme Wind Warning|Tornado Emergency|Flash Flood Emergency|Storm Surge Warning)/;

/** Tsunami bulletins (US warning centers) and extreme or severe US weather alerts (NWS). */
export async function bulletins(ctx: Ctx, days = 2): Promise<{ data: Bulletin[]; prov: import('../core/types.js').Provenance[] }> {
  const since = ctx.now().getTime() - days * 86_400_000;
  const out: Bulletin[] = [];
  const prov: import('../core/types.js').Provenance[] = [];
  for (const [src, url] of TSUNAMI_FEEDS) {
    const r = await ctx.http.get<string>(url, { source: 'tsunami-gov', as: 'text', ttlSec: 600 });
    prov.push(r.prov);
    for (const e of (r.data ?? '').split('<entry>').slice(1)) {
      const updated = /<updated>([^<]+)<\/updated>/.exec(e)?.[1] ?? '';
      if (!updated || Date.parse(updated) < since) continue;
      const category = /Category:<\/strong>\s*([^<]+)/.exec(e)?.[1]?.trim() ?? 'Information';
      const link = /<link[^>]*href="([^"]+)"/.exec(e)?.[1] ?? 'https://www.tsunami.gov';
      out.push({ source: src, title: (/<title>([^<]+)<\/title>/.exec(e)?.[1] ?? '').trim(), category, area: (/Affected Region:\s*<\/strong>\s*([^<]+)/.exec(e)?.[1] ?? '').trim(), issued: updated, url: link });
    }
  }
  const nws = await ctx.http.get<{ features?: { properties: { event: string; severity: string; areaDesc: string; sent: string; headline?: string; id?: string } }[] }>(
    'https://api.weather.gov/alerts/active?severity=Extreme,Severe&status=actual&message_type=alert',
    { source: 'nws', ttlSec: 600, headers: { accept: 'application/geo+json' } },
  );
  prov.push(nws.prov);
  for (const f of nws.data?.features ?? []) {
    const p = f.properties;
    out.push({ source: 'NWS', title: p.event, category: p.severity, area: p.areaDesc.slice(0, 160), issued: p.sent, url: p.id ?? 'https://alerts.weather.gov' });
  }
  return { data: out, prov };
}

export async function hazards(ctx: Ctx, days = 7): Promise<ModuleResult<Hazard[] & { bulletins?: Bulletin[] }>> {
  const now = ctx.now();
  const from = new Date(now.getTime() - days * 86_400_000).toISOString().slice(0, 10);
  const r = await ctx.http.get<{ features?: { geometry?: { coordinates?: [number, number] }; properties: { eventtype: string; eventid: number; episodeid?: number; name: string; alertlevel: string; country?: string; fromdate: string; todate: string; iscurrent?: boolean | string; severitydata?: { severitytext?: string }; url?: { report?: string } } }[] }>(
    `https://www.gdacs.org/gdacsapi/api/events/geteventlist/SEARCH?alertlevel=Orange;Red&eventlist=EQ;TC;FL;VO;DR;WF&fromDate=${from}`,
    { source: 'gdacs', ttlSec: 1800, timeoutMs: 45_000 },
  );
  const list: Hazard[] = (r.data?.features ?? []).map((f) => {
    const p = f.properties;
    return {
      id: `${p.eventtype}-${p.eventid}`,
      type: TYPES[p.eventtype] ?? p.eventtype,
      name: p.name,
      level: (['Red', 'Orange', 'Green'].includes(p.alertlevel) ? p.alertlevel : 'Orange') as Hazard['level'],
      countries: p.country ?? '',
      from: p.fromdate,
      to: p.todate,
      current: p.iscurrent === true || p.iscurrent === 'true',
      severity: p.severitydata?.severitytext ?? '',
      lat: f.geometry?.coordinates?.[1] ?? null,
      lon: f.geometry?.coordinates?.[0] ?? null,
      url: p.url?.report ?? 'https://www.gdacs.org',
    };
  });
  list.sort((a, b) => Number(b.level === 'Red') - Number(a.level === 'Red') || b.to.localeCompare(a.to));
  const signals: Signal[] = list
    .filter((h) => h.current || now.getTime() - Date.parse(`${h.to}Z`) < 2 * 86_400_000)
    .map((h) => ({
      id: signalId('hazards', h.id, h.level),
      module: 'hazards',
      title: `GDACS ${h.level.toLowerCase()} alert: ${h.name}${h.countries ? ` (${h.countries})` : ''}`,
      score: h.level === 'Red' ? 82 : 66,
      evidence: [{ source: 'gdacs', text: `${h.type}${h.severity ? `, ${h.severity}` : ''}, ${h.from.slice(0, 10)} to ${h.to.slice(0, 10)}`, url: h.url }],
      createdAt: now.toISOString(),
    }));
  const b = await bulletins(ctx, 2);
  for (const x of b.data) {
    const tsunamiThreat = x.source !== 'NWS' && /warning|advisory|watch|threat/i.test(x.category);
    if (!tsunamiThreat && !(x.source === 'NWS' && NWS_SIGNAL.test(x.title))) continue;
    signals.push({
      id: signalId('hazards', x.source, x.title, x.area.slice(0, 60), x.issued.slice(0, 13)),
      module: 'hazards',
      title: x.source === 'NWS' ? `${x.title}: ${x.area.split(';').slice(0, 3).join(';')}` : `Tsunami ${x.category.toLowerCase()}: ${x.title}`,
      score: tsunamiThreat && /warning/i.test(x.category) ? 88 : 72,
      evidence: [{ source: x.source === 'NWS' ? 'nws' : 'tsunami-gov', text: `${x.category}, issued ${x.issued.slice(0, 16).replace('T', ' ')} UTC${x.area ? `, ${x.area.slice(0, 120)}` : ''}`, url: x.url }],
      createdAt: now.toISOString(),
    });
  }
  for (const s of signals) ctx.graph.saveSignal(s);
  const result = Object.assign(list, { bulletins: b.data });
  return { module: 'hazards', input: `${days}d`, generatedAt: now.toISOString(), result, signals, provenance: [r.prov, ...b.prov] };
}
