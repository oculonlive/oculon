/**
 * IP check: who runs this address, and is it known for abuse?
 * Location and network (ip-api.com, IPinfo Lite, PeeringDB), abuse reports (AbuseIPDB), internet scanning
 * (GreyNoise), threat reports (AlienVault OTX), antivirus verdicts (VirusTotal), malware infrastructure
 * (ThreatFox), hijacked or criminal networks (Spamhaus DROP), Tor exits and open ports (Shodan InternetDB).
 * A domain is resolved to its first address first.
 */
import { isIP } from 'node:net';
import type { Ctx } from '../core/context.js';
import { clamp } from '../core/stats.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import {
  abuseIpDb, greyNoise, inCidr, internetDb, ipApi, ipInfo, isPublicIp, otx, peeringDb, spamhausDrop, threatFox, torExits, virusTotal,
  type AbuseIpDb, type GreyNoise, type InternetDb, type IpApi, type OtxPulses, type PeeringNet, type ThreatFoxHit, type VtStats,
} from '../sources/threatintel.js';

export type IpVerdict = 'malicious' | 'suspicious' | 'no known abuse';

export interface IpCheck {
  ip: string;
  resolvedFrom: string | null;
  verdict: IpVerdict;
  risk: number;
  reasons: string[];
  location: { country: string | null; countryCode: string | null; region: string | null; city: string | null } | null;
  network: { asn: string | null; name: string | null; isp: string | null; domain: string | null; type: string | null; reverse: string | null };
  flags: { tor: boolean; proxy: boolean; hosting: boolean; mobile: boolean; scanner: boolean; knownGood: boolean };
  abuseipdb: AbuseIpDb | null;
  greynoise: GreyNoise | null;
  otx: OtxPulses | null;
  virustotal: VtStats | null;
  threatfox: ThreatFoxHit[];
  drop: { listed: boolean; entry: string | null; asnListed: boolean };
  ports: InternetDb | null;
  advice: string[];
}

async function resolve(ctx: Ctx, host: string): Promise<{ ip: string | null; prov: Provenance }> {
  for (const type of ['A', 'AAAA']) {
    const r = await ctx.http.get<{ Answer?: { type: number; data: string }[] }>(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=${type}`, { source: 'google-dns', ttlSec: 1800 });
    const ip = (r.data?.Answer ?? []).find((a) => a.type === (type === 'A' ? 1 : 28))?.data;
    if (ip) return { ip, prov: r.prov };
    if (type === 'AAAA') return { ip: null, prov: r.prov };
  }
  return { ip: null, prov: { source: 'google-dns', url: '', status: 'ERROR', fetchedAt: new Date().toISOString() } };
}

/** Plain-language reasons and a 0-100 risk from the source answers. */
export function scoreIp(x: Pick<IpCheck, 'abuseipdb' | 'greynoise' | 'otx' | 'virustotal' | 'threatfox' | 'drop' | 'flags'>): { risk: number; verdict: IpVerdict; reasons: string[] } {
  const reasons: string[] = [];
  let risk = 0;
  if (x.drop.listed) { risk = Math.max(risk, 95); reasons.push(`on the Spamhaus DROP list (${x.drop.entry}): a network run by or hijacked for criminals`); }
  if (x.drop.asnListed) { risk = Math.max(risk, 85); reasons.push('its network (ASN) is on the Spamhaus ASN-DROP list'); }
  if (x.threatfox.length) { risk = Math.max(risk, 85); reasons.push(`ThreatFox lists it as malware infrastructure${x.threatfox[0]!.malware ? ` (${x.threatfox[0]!.malware})` : ''}`); }
  const a = x.abuseipdb;
  if (a && a.reports > 0) {
    risk = Math.max(risk, a.score >= 75 ? 85 : a.score >= 25 ? 55 : a.score > 0 ? 25 : 10);
    reasons.push(`${a.reports} abuse report${a.reports === 1 ? '' : 's'} from ${a.reporters} reporter${a.reporters === 1 ? '' : 's'} in 90 days (AbuseIPDB confidence ${a.score}%)`);
  }
  const g = x.greynoise;
  if (g?.noise) {
    risk = Math.max(risk, g.classification === 'malicious' ? 70 : 30);
    reasons.push(`GreyNoise sees it scanning the internet${g.classification ? `, classified ${g.classification}` : ''}${g.name ? ` (${g.name})` : ''}`);
  }
  const v = x.virustotal;
  if (v && v.malicious > 0) {
    risk = Math.max(risk, v.malicious >= 8 ? 80 : v.malicious >= 3 ? 50 : 15);
    reasons.push(`${v.malicious} of ${v.engines} VirusTotal engines flag it`);
  }
  const o = x.otx;
  if (o && o.count > 0 && !o.whitelisted) {
    risk = Math.max(risk, o.count >= 10 ? 45 : 20);
    reasons.push(`mentioned in ${o.count} AlienVault OTX threat report${o.count === 1 ? '' : 's'}`);
  }
  if (x.flags.tor) { risk = Math.max(risk, 40); reasons.push('a Tor exit node: traffic from it can come from anyone'); }
  if (x.flags.proxy && !x.flags.knownGood) reasons.push('a known proxy or VPN address');
  // Big shared services (Google DNS, Cloudflare) collect stray reports; say so instead of alarming.
  if (x.flags.knownGood) { risk = Math.min(risk, 20); reasons.push('a known benign service (allow-listed by AbuseIPDB, GreyNoise or OTX)'); }
  risk = clamp(Math.round(risk), 0, 100);
  return { risk, verdict: risk >= 70 ? 'malicious' : risk >= 35 ? 'suspicious' : 'no known abuse', reasons };
}

export async function ipCheck(ctx: Ctx, input: string): Promise<ModuleResult<IpCheck>> {
  const raw = input.trim().replace(/^\[|\]$/g, '');
  if (!raw) throw new Error('missing IP address or domain');
  const provenance: Provenance[] = [];
  let ip = raw;
  let resolvedFrom: string | null = null;
  if (!isIP(raw)) {
    const host = raw.toLowerCase().replace(/^https?:\/\//, '').replace(/[/:?#].*$/, '');
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) throw new Error(`not an IP address or domain: ${input}`);
    const r = await resolve(ctx, host);
    provenance.push(r.prov);
    if (!r.ip) throw new Error(`domain not found: ${host} has no IP address`);
    ip = r.ip;
    resolvedFrom = host;
  }
  if (!isPublicIp(ip)) throw new Error(`not a public IP address: ${ip} is private, reserved or local`);
  const v6 = isIP(ip) === 6;

  const [loc, info, abuse, gn, ox, vt, tf, tor, drop, ports] = await Promise.all([
    ipApi(ctx, ip), ipInfo(ctx, ip), abuseIpDb(ctx, ip), greyNoise(ctx, ip), otx(ctx, v6 ? 'IPv6' : 'IPv4', ip), virusTotal(ctx, 'ip', ip), threatFox(ctx, 'ioc', ip), torExits(ctx), spamhausDrop(ctx), internetDb(ctx, ip),
  ]);
  provenance.push(loc.prov, info.prov, abuse.prov, gn.prov, ox.prov, vt.prov, tf.prov, tor.prov, ...drop.prov, ports.prov);

  const asnNum = Number((info.data?.asn ?? loc.data?.as ?? '').replace(/^AS/i, '').split(/\s/)[0]);
  let pdb: PeeringNet | null = null;
  if (Number.isInteger(asnNum) && asnNum > 0) {
    const p = await peeringDb(ctx, asnNum);
    provenance.push(p.prov);
    pdb = p.data;
  }
  const dropEntry = drop.data?.cidrs.find((c) => inCidr(ip, c.cidr)) ?? null;
  const loc2: IpApi | null = loc.data;
  const flags = {
    tor: Boolean(tor.data?.has(ip) || abuse.data?.isTor),
    proxy: Boolean(loc2?.proxy),
    hosting: Boolean(loc2?.hosting),
    mobile: Boolean(loc2?.mobile),
    scanner: Boolean(gn.data?.noise),
    knownGood: Boolean(abuse.data?.whitelisted || gn.data?.riot || ox.data?.whitelisted),
  };
  const part = {
    abuseipdb: abuse.data, greynoise: gn.data, otx: ox.data, virustotal: vt.data, threatfox: tf.data ?? [], flags,
    drop: { listed: Boolean(dropEntry), entry: dropEntry ? `${dropEntry.cidr}${dropEntry.id ? ` ${dropEntry.id}` : ''}` : null, asnListed: Boolean(asnNum && drop.data?.asns.some((x) => x.asn === asnNum)) },
  };
  const { risk, verdict, reasons } = scoreIp(part);
  const advice: string[] = [];
  if (verdict === 'malicious') advice.push('Block this address at your firewall or mail server, and check your logs for earlier connections from it.');
  else if (verdict === 'suspicious') advice.push('Treat connections from this address with care: rate limit it, and watch for login attempts or scans.');
  else advice.push('No source reports abuse from this address. That is not a guarantee: new addresses have no history yet.');
  if (flags.tor) advice.push('Tor exits are shared by many users; blocking one blocks all of them, not just the bad actor.');
  if (ports.data?.vulns.length) advice.push(`Shodan lists ${ports.data.vulns.length} known vulnerabilit${ports.data.vulns.length === 1 ? 'y' : 'ies'} on its open ports; if this is your server, patch it.`);

  return {
    module: 'ipcheck',
    input: resolvedFrom ?? ip,
    generatedAt: ctx.now().toISOString(),
    result: {
      ip,
      resolvedFrom,
      verdict,
      risk,
      reasons,
      location: loc2 ? { country: loc2.country, countryCode: loc2.countryCode, region: loc2.region, city: loc2.city } : info.data ? { country: info.data.country, countryCode: info.data.countryCode, region: null, city: null } : null,
      network: { asn: info.data?.asn ?? (loc2?.as?.split(' ')[0] ?? null), name: info.data?.asName ?? pdb?.name ?? loc2?.org ?? null, isp: loc2?.isp ?? abuse.data?.isp ?? null, domain: info.data?.asDomain ?? abuse.data?.domain ?? null, type: pdb?.type ?? abuse.data?.usageType ?? null, reverse: loc2?.reverse ?? null },
      ...part,
      ports: ports.data,
      advice,
    },
    signals: [],
    provenance,
  };
}
