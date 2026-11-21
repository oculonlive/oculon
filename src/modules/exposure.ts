/**
 * Exposure: what a domain shows to the internet. Resolves the domain, common service hosts and subdomains
 * Oculon has already seen, then asks Shodan InternetDB (free, no key) about each IP: open ports, software
 * (CPEs), known vulnerabilities (CVEs) and other hostnames on the same machine.
 * Shared CDN edges (Cloudflare, Akamai, Fastly...) are marked, since their ports and CVEs describe the CDN.
 */
import { enc, type Ctx } from '../core/context.js';
import { signalId } from '../core/text.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { ipRouting } from './bgp.js';
import { kevSet } from './vulns.js';

export interface ExposedIp {
  ip: string;
  hosts: string[];
  ports: number[];
  vulns: string[];
  cpes: string[];
  otherHostnames: string[];
  cdn: string | null;
  /** CVEs on this IP that CISA lists as exploited in the wild (KEV). */
  exploited?: string[];
  /** Announcing network, abuse contact and RPKI validity (RIPEstat), for the first few non-CDN IPs. */
  network?: { origin: string | null; abuse: string[]; rpki: string | null; country: string | null } | null;
}

export interface Exposure {
  domain: string;
  hostsChecked: number;
  resolved: number;
  ips: ExposedIp[];
  /** Ports other than 80/443 on non-CDN machines: admin panels, databases, remote access. */
  unusualPorts: { ip: string; port: number; hosts: string[] }[];
  vulns: number;
  /** Distinct CVEs on non-CDN machines that are in CISA's Known Exploited Vulnerabilities catalog. */
  exploited?: string[];
}

const PREFIXES = ['', 'www', 'api', 'app', 'mail', 'dev', 'staging', 'admin', 'vpn', 'portal', 'status', 'docs', 'beta'];
const RISKY: Record<number, string> = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 445: 'SMB', 1433: 'MSSQL', 2375: 'Docker API', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP alt', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB' };

export function cdnOf(cpes: string[], hostnames: string[]): string | null {
  const s = `${cpes.join(' ')} ${hostnames.join(' ')}`.toLowerCase();
  for (const [needle, name] of [['cloudflare', 'Cloudflare'], ['akamai', 'Akamai'], ['fastly', 'Fastly'], ['cloudfront', 'Amazon CloudFront'], ['edgecast', 'Edgio'], ['vercel', 'Vercel'], ['netlify', 'Netlify'], ['azurefd', 'Azure Front Door'], ['googleusercontent', 'Google Cloud']] as const) if (s.includes(needle)) return name;
  return null;
}

export async function exposure(ctx: Ctx, domainInput: string): Promise<ModuleResult<Exposure>> {
  const domain = domainInput.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const now = ctx.now();
  const provenance: Provenance[] = [];
  const known = (ctx.store.db.prepare("SELECT name FROM entities WHERE kind = 'subdomain' AND name LIKE ? LIMIT 40").all(`%.${domain}`) as { name: string }[]).map((r) => r.name.toLowerCase());
  const hosts = [...new Set([...PREFIXES.map((p) => (p ? `${p}.${domain}` : domain)), ...known])].slice(0, 40);

  const byIp = new Map<string, Set<string>>();
  await Promise.all(
    hosts.map(async (h) => {
      const r = await ctx.http.get<{ Answer?: { type: number; data: string }[] }>(`https://dns.google/resolve?name=${enc(h)}&type=A`, { source: 'dns-google', ttlSec: 3600 });
      if (r.prov.status === 'ERROR') provenance.push(r.prov);
      for (const a of r.data?.Answer ?? []) if (a.type === 1) byIp.set(a.data, (byIp.get(a.data) ?? new Set()).add(h));
    }),
  );
  provenance.push({ source: 'dns-google', url: 'https://dns.google/resolve', status: 'LIVE', fetchedAt: now.toISOString(), note: `${hosts.length} hosts, ${byIp.size} IPs` });

  const ips: ExposedIp[] = [];
  await Promise.all(
    [...byIp].slice(0, 25).map(async ([ip, hs]) => {
      const r = await ctx.http.get<{ ports?: number[]; vulns?: string[]; cpes?: string[]; hostnames?: string[] }>(`https://internetdb.shodan.io/${ip}`, { source: 'shodan-internetdb', ttlSec: 12 * 3600 });
      if (r.prov.status !== 'UNAVAILABLE') provenance.push(r.prov);
      const d = r.data ?? {};
      const hostnames = d.hostnames ?? [];
      ips.push({ ip, hosts: [...hs].sort(), ports: (d.ports ?? []).sort((a, b) => a - b), vulns: d.vulns ?? [], cpes: d.cpes ?? [], otherHostnames: hostnames.filter((x) => !x.endsWith(domain)).slice(0, 8), cdn: cdnOf(d.cpes ?? [], hostnames) });
    }),
  );
  ips.sort((a, b) => b.vulns.length - a.vulns.length || b.ports.length - a.ports.length);
  // Who runs the first machines and where to report abuse. The announcing network is more reliable than
  // InternetDB hostnames (shared IPs list other sites' names) for telling a CDN edge from a direct server.
  await Promise.all(
    ips.slice(0, 8).map(async (x) => {
      const r = await ipRouting(ctx, x.ip);
      provenance.push(...r.prov.filter((p) => p.status === 'ERROR'));
      x.network = r.data ? { origin: r.data.origins.map((o) => `${o.name} (${o.asn})`).join(', ') || null, abuse: r.data.abuse, rpki: r.data.rpki, country: r.data.country } : null;
      const byNetwork = x.network?.origin ? cdnOf([], [x.network.origin]) : null;
      if (byNetwork && byNetwork !== 'Google Cloud') x.cdn = byNetwork;
      else if (x.network?.origin && x.cdn && !cdnOf([], [x.network.origin])) {
        // Labelled a CDN only from hostnames of other sites on a shared IP: keep the label only if the CPEs agree.
        x.cdn = cdnOf(x.cpes, []);
      }
    }),
  );
  const unusualPorts = ips.filter((x) => !x.cdn).flatMap((x) => x.ports.filter((p) => p !== 80 && p !== 443).map((port) => ({ ip: x.ip, port, hosts: x.hosts })));
  const vulns = ips.filter((x) => !x.cdn).reduce((n, x) => n + x.vulns.length, 0);

  // Which of those CVEs are being exploited in the wild (CISA KEV, one cached catalog download).
  let exploited: string[] = [];
  if (vulns > 0) {
    const kev = await kevSet(ctx);
    provenance.push({ source: 'cisa-kev', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', status: kev.size ? 'LIVE' : 'UNAVAILABLE', fetchedAt: now.toISOString(), note: `${kev.size} exploited CVEs in catalog` });
    for (const x of ips) x.exploited = x.vulns.filter((v) => kev.has(v.toUpperCase()));
    exploited = [...new Set(ips.filter((x) => !x.cdn).flatMap((x) => x.exploited ?? []))].sort();
  }

  const signals: Signal[] = [];
  const risky = unusualPorts.filter((p) => RISKY[p.port]);
  if (vulns > 0 || risky.length) {
    signals.push({
      id: signalId('exposure', domain, now.toISOString().slice(0, 10)),
      module: 'exposure',
      title: `${domain}: ${vulns} known vulnerabilit${vulns === 1 ? 'y' : 'ies'}${exploited.length ? ` (${exploited.length} exploited in the wild)` : ''}${risky.length ? `, exposed ${[...new Set(risky.map((p) => RISKY[p.port]))].join(', ')}` : ''}`,
      score: Math.min(90, 45 + Math.min(vulns, 10) * 3 + risky.length * 5 + Math.min(exploited.length, 3) * 6),
      evidence: ips
        .filter((x) => !x.cdn && (x.vulns.length || x.ports.some((p) => RISKY[p])))
        .slice(0, 4)
        .map((x) => ({ source: 'shodan-internetdb', text: `${x.hosts.join(', ')} (${x.ip}): ports ${x.ports.join(', ')}${x.vulns.length ? `; ${x.vulns.slice(0, 5).join(', ')}` : ''}${x.exploited?.length ? `; exploited in the wild (CISA KEV): ${x.exploited.slice(0, 4).join(', ')}` : ''}${x.network?.origin ? `; network ${x.network.origin}` : ''}`, url: `https://internetdb.shodan.io/${x.ip}` })),
      createdAt: now.toISOString(),
    });
  }
  for (const s of signals) ctx.graph.saveSignal(s);
  return { module: 'exposure', input: domain, generatedAt: now.toISOString(), result: { domain, hostsChecked: hosts.length, resolved: byIp.size, ips, unusualPorts, vulns, exploited }, signals, provenance };
}
