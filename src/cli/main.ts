/**
 * The `oculon` command-line interface. Zero dependencies: ANSI colors (honoring NO_COLOR and pipes),
 * plain tables, and --json on every command for scripting.
 */
import { existsSync, readFileSync, copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { oculonHome } from '../core/paths.js';
import { fmtTime } from '../modules/listen.js';
import type { ModuleResult } from '../core/types.js';
import { Oculon, summarizeProvenance, type Signal } from '../index.js';
import { ONCHAIN_COMMANDS, ONCHAIN_PAUSED_MESSAGE, onchainEnabled } from '../core/features.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const VERSION = (() => {
  for (const p of [join(HERE, '..', '..', 'package.json'), join(HERE, '..', 'package.json')]) {
    try {
      return (JSON.parse(readFileSync(p, 'utf8')) as { version: string }).version;
    } catch {}
  }
  return '0.0.0';
})();

/* ---------- tiny terminal toolkit ---------- */
const COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string) => (s: string | number) => (COLOR ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = { bold: paint('1'), dim: paint('2'), red: paint('31'), green: paint('32'), yellow: paint('33'), blue: paint('34'), magenta: paint('35'), cyan: paint('36'), gray: paint('90') };
const out = (s = '') => process.stdout.write(`${s}\n`);
const score = (n: number) => {
  const s = String(Math.round(n)).padStart(3);
  return n >= 75 ? c.red(s) : n >= 55 ? c.yellow(s) : c.green(s);
};
const pct = (x: number | null | undefined) => (x == null ? 'n/a' : `${Math.round(x * 100)}%`);
const trunc = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

function printSignals(signals: Signal[], max = 10) {
  for (const s of signals.slice(0, max)) {
    out(`  [${score(s.score)}] ${c.bold(s.title)} ${c.gray(s.module)}`);
    for (const e of s.evidence.slice(0, 3)) out(`        ${c.cyan(e.source)} ${trunc(e.text, 110)}`);
  }
}

function printTranscript(t: import('../modules/listen.js').Transcript) {
  out(c.bold(`\n${t.title ?? t.url}`) + c.dim(`  ${fmtTime(t.durationSec)} · ${t.language ?? '?'} · ${t.words} words`));
  if (t.summary) out(`\n  ${c.dim('machine summary')} ${t.summary}`);
  if (t.topics.length) out(`  ${c.dim('topics')} ${t.topics.join(', ')}`);
  if (t.mentions.length) {
    out(c.bold('\n  Mentions'));
    for (const m of t.mentions) out(`  ${c.cyan(fmtTime(m.start))} ${trunc(m.text, 260)}`);
  } else if (t.opening.length) {
    out(c.bold('\n  Opening'));
    for (const m of t.opening) out(`  ${c.cyan(fmtTime(m.start))} ${trunc(m.text, 200)}`);
  }
}

function printSources(r: ModuleResult<unknown>) {
  const { sources, notes } = summarizeProvenance(r.provenance);
  const parts = Object.entries(sources).map(([src, st]) => {
    const bad = st.ERROR || st.UNAVAILABLE;
    const label = Object.entries(st)
      .map(([k, v]) => `${k.toLowerCase()}${v > 1 ? `×${v}` : ''}`)
      .join(' ');
    return `${bad ? c.yellow(src) : c.gray(src)} ${c.dim(label)}`;
  });
  out(`\n${c.dim('sources')} ${parts.join(c.dim('  ·  '))}`);
  for (const n of notes.slice(0, 6)) out(c.dim(`  ${trunc(n, 140)}`));
}

/* ---------- argument parsing ---------- */
interface Args {
  pos: string[];
  flags: Record<string, string | true>;
}

export function parseArgs(argv: string[]): Args {
  const pos: string[] = [];
  const flags: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=', 2) as [string, string | undefined];
      if (v !== undefined) flags[k] = v;
      else if (argv[i + 1] !== undefined && !argv[i + 1]!.startsWith('--') && !BOOLEAN.has(k)) flags[k] = argv[++i]!;
      else flags[k] = true;
    } else pos.push(a);
  }
  return { pos, flags };
}
const BOOLEAN = new Set(['json', 'help', 'no-github', 'no-org', 'version', 'live', 'telegram', 'radar', 'deep', 'dry-run', 'all', 'public']);

/** Help without the paused on-chain commands (they come back with OCULON_ONCHAIN=1). */
function helpText(): string {
  if (onchainEnabled()) return HELP;
  return HELP.split('\n')
    .filter((l) => !/oculon (rh|deployer|wallet|token|defi|protocol)\b|@robinhood|On-chain/.test(l))
    .join('\n')
    .replace(/\n{3,}/g, '\n\n');
}

const HELP = `${c.bold('oculon')} ${c.dim(`v${VERSION}`)} — OSINT intelligence engine for AI agents

${c.bold('Ask')}
  oculon ask "<question>"              AI agent answers using every Oculon tool  (octopus)

${c.bold('Analysis')}
  oculon narratives [run]              storylines across days, new and growing ones flagged
  oculon health <company>              early-warning score 0-100 with each part explained
  oculon impact [place] [--radius 50]  people exposed to current M6+ quakes and severe storms
  oculon contradictions <topic>        conflicting facts across independent sources
  oculon report [--days 7] [--out f]   self-contained HTML report of the period
  oculon plugin [list] | run <name.tool> [--args '{}']   local plugins

${c.bold('Markets, launches, history')}
  oculon sanctions <wallet|IMO|name>   OFAC sanctions screening (wallet also checks counterparties)
  oculon markets [--gap 15]            Polymarket vs Kalshi and Manifold on the same questions  (lynx)
  oculon launches <company> [--domain x.com] [--org handle]  new models, apps, packages, hosts
  oculon rewind <YYYY-MM-DD>           time machine: what Oculon would have seen that day
  oculon calibrate [--days 10]         replay past days, measure which signals became news, tune the radar

${c.bold('Geofences')}
  oculon fence add <name> <place> [--radius 100] [--kinds air,sea,quake,events]
  oculon fence [list] | check | rm <id>  report what is new inside each box

${c.bold('First to know')}
  oculon scoops [check]                lead time of Oculon signals vs first media coverage

${c.bold('Case files')}
  oculon case new "<question>"         deep investigation with sourced findings
  oculon case [list] | show <id> | rerun <id> | watch <id> [off]

${c.bold('Watch & brief')}
  oculon watch add <kind> <target>     kinds: company domain plane topic lights air port news outage cve quake hazard url package travel
  oculon watch [list] | run | rm <id>  re-check targets, report only what changed   (meerkat)
  oculon brief [--refresh]             today's brief from signals and watch changes
  oculon sentinel <place> [--date d] [--compare d] [--radar] [--out f.png]  10 m satellite image, before/after
  oculon fires <place> [--days 2]      active fires and hotspots (NASA FIRMS)
  oculon darkships <place> [--days 30]  vessels that switched off AIS there (Global Fishing Watch)
  oculon vessel <name|MMSI|IMO>        flag history, owners, earlier names, sanctions
  oculon cloud                         outages on AWS, Azure, Google Cloud, GitHub, Cloudflare, OpenAI...
  oculon bgp [world|cc|ASN|IP]         BGP hijacks, route leaks, DDoS targets; routing of a country, network or IP
  oculon vulns [days] [--vendor x]     newly exploited CVEs (CISA KEV), new critical CVEs, package advisories
  oculon cve <CVE-id>                  CVSS, exploitation odds (EPSS), KEV status, affected packages and fixes
  oculon pkg <ecosystem> <name> [ver]  known vulnerabilities of a package (OSV.dev)
  oculon regs [query] [--agency x]     US Federal Register: executive orders, rules, tomorrow's documents
  oculon defi                          TVL crashes, stablecoin depegs, hacks, fear and greed (DefiLlama)
  oculon protocol <name>               one DeFi protocol: TVL trend, drawdown, audits, hacks, warnings
  oculon squawk                        aircraft squawking 7500 hijack / 7600 radio / 7700 emergency now
  oculon filings "<phrase>" [--forms 8-K] [--days 30]  SEC EDGAR full-text search
  oculon edgar <ticker>                a company's 8-K events in plain English (CEO exits, restatements...)
  oculon blackout [days]               internet outages and shutdowns (Cloudflare Radar, IODA)
  oculon hazards [days]                official orange/red disaster alerts (GDACS)
  oculon podcast <subject> [--pick n]  newest podcast episode about it, transcribed, timestamped quotes
  oculon listen <media-url> [--about x]  transcribe any audio/video file URL (Deepgram)
  oculon exposure <domain>             open ports, software and known CVEs on its servers
  oculon social <subject> [--only x,reddit,tiktok,bluesky]  posts right now, pace, most engaged
  oculon calendar [days]               earnings, macro releases, markets closing soon
  oculon feedback [useful|noise <id>]  votes that move each module's alert bar

${c.bold('Live')}
  oculon live [--minutes 30]           Wikipedia edit surges + Bluesky term surges in real time

${c.bold('Graph')}
  oculon connect <A> to <B>            how two things are linked (shortest path)
  oculon resolve                       merge duplicates: org:nvidia = company:nvidia = nvidia.com
  oculon quota                         today's API usage vs daily budgets

${c.bold('Radar')}
  oculon radar                         what the world is suddenly paying attention to
  oculon signals [--limit 20]          latest signals from every module

${c.bold('On-chain')}
  oculon wallet <address>              portfolio, age, risk, Robinhood Chain   (magpie)
  oculon token <address> [--chain eth|base|arbitrum|bsc|polygon|robinhood]  token risk check
  oculon rh                            Robinhood Chain: activity, trending and new pools (heron)
  oculon deployer <address>            Robinhood Chain deployer reputation (serial launchers)

${c.bold('Earth & sky')}
  oculon space                         geomagnetic storms and solar flares
  oculon air <place>                   PM2.5 air quality near a place

${c.bold('Everyday checks')}
  oculon scam "<message>"              is this SMS, email or chat message a scam?
  oculon url <link>                    is a link dangerous? Safe Browsing, URLhaus, urlscan, domain age
  oculon factcheck "<claim>"|<url>     fact check a claim or a news link
  oculon audit [file|npm:name@ver ...] dependency health: vulnerabilities, deprecation, Scorecard
  oculon travel <place>                travel risk brief for the coming week
  oculon monitor "<request>"           watch anything in plain language, e.g. "outages in Iran"
  oculon recall <VIN|"year make model"|product>  vehicle and product recalls (NHTSA, CPSC, FDA)
  oculon email <domain>                can someone spoof email from this domain? with fixes
  oculon papers "<topic>"              research brief: most cited and newest papers
  oculon country <name>                country brief: economy, leaders, currency, advice, news
  oculon airport <JFK|EGLL|name>       airport weather, FAA delays and ground stops
  oculon phone <+number> [--country US]  who is calling? country, line type, premium-rate and callback-scam warnings
  oculon password                      has this password leaked? (asked without echo; k-anonymity)
  oculon breaches [domain]             newest data breaches, or every breach of one domain (HIBP)
  oculon company <name|LEI|EU VAT>     is this supplier real? VAT check (VIES), LEI register (GLEIF)

${c.bold('Threat intel')}
  oculon ip <IP|domain>                abuse reports, scanners, threat reports, Tor, Spamhaus DROP, open ports
  oculon hash <md5|sha1|sha256>        is this file known malware or a known good file?
  oculon ransomware [CC|sector|name]   ransomware leak-site claims, newest first
  oculon satellite [name|NORAD id]     launches of the last 30 days, or one object's orbit (CelesTrak)

${c.bold('Web')}
  oculon search <query>                web search
  oculon read <url>                    readable text of a page

${c.bold('Investigate')}
  oculon dossier <name>                company / person / project dossier      (hound)
  oculon hype <topic>                  hype-cycle phase of a topic             (cricket)
  oculon footprint <domain> [--days]   pre-release footprints of a domain      (ferret)
  oculon plane <registration|hex>      track one aircraft                      (falcon)
  oculon mil                           military air traffic worldwide          (falcon)
  oculon ships <place> [--seconds 30]  live vessels near a port or strait (AIS)
  oculon ship <mmsi>                   follow one ship
  oculon events                        natural events from NASA                (condor)
  oculon lights <place>                night lights vs baseline (blackouts)    (condor)
  oculon image <place> [--date] [--out file.png]  satellite image            (condor)
  oculon entity <id>                   entity and neighbors, e.g. org:nvidia

${c.bold('Forecasts & proofs')}
  oculon forecast <market-slug> --p 0.35 [--why "..."]   record a forecast  (raven)
  oculon forecast auto | resolve | score | list
  oculon proof stamp                   timestamp forecasts on Bitcoin     (tortoise)
  oculon proof verify <forecast-id>    verify down to the Bitcoin block

${c.bold('Run')}
  oculon serve [--port 4747] [--watch 15] [--telegram] [--live] [--host 0.0.0.0 --public]   web app on 127.0.0.1; --public opens a read-only overview
  oculon mcp                                MCP server on stdio (for Claude and other agents)
  oculon telegram                           Telegram bot (TELEGRAM_BOT_TOKEN, TELEGRAM_ALLOWED_CHATS)
  oculon doctor                             check setup and every data source
  oculon tour                               what this install knows and what to try next
  oculon gc [--days 14]                     drop old cached API responses, compact the database

Every command accepts ${c.bold('--json')}. Data lives in ${oculonHome()} (set OCULON_HOME to change).
Optional settings: OCULON_CONTACT (enables SEC EDGAR), GITHUB_TOKEN.`;

/* ---------- commands ---------- */
type Cmd = (o: Oculon, a: Args) => Promise<unknown>;

const need = (a: Args, i: number, what: string): string => {
  const v = a.pos.slice(i).join(' ').trim();
  if (!v) throw new UsageError(`missing ${what}`);
  return v;
};

class UsageError extends Error {}

/** Read one line from the terminal without echoing it (for passwords). */
function readHidden(prompt: string): Promise<string> {
  return new Promise((resolveLine) => {
    const stdin = process.stdin;
    process.stdout.write(prompt);
    let buf = '';
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const done = (v: string) => {
      stdin.setRawMode?.(false);
      stdin.pause();
      stdin.removeListener('data', onData);
      process.stdout.write('\n');
      resolveLine(v);
    };
    const onData = (ch: string) => {
      for (const k of ch) {
        if (k === '\r' || k === '\n') return done(buf);
        if (k === '\u0003') { done(''); process.exit(130); }
        if (k === '\u007f' || k === '\b') buf = buf.slice(0, -1);
        else buf += k;
      }
    };
    stdin.on('data', onData);
  });
}

const json = (a: Args) => a.flags.json === true;
const emit = (a: Args, data: unknown, human: () => void) => (json(a) ? out(JSON.stringify(data, null, 2)) : human());

export const COMMANDS: Record<string, Cmd> = {
  async radar(o, a) {
    const r = await o.radar();
    emit(a, r, () => {
      out(c.bold(`Radar · ${r.result.blips.length} anomalies, ${r.signals.length} signals`));
      for (const f of r.result.fused.slice(0, 12)) {
        out(`  [${score(f.score)}] ${c.bold(trunc(f.title, 90))} ${c.gray(f.sources.join(' + '))}`);
        if (f.linkedBy) out(c.dim(`        linked by AI (${trunc(f.linkedBy, 110)})`));
        for (const b of f.blips.slice(0, 3)) out(`        ${c.cyan(b.source)} ${f.linkedBy ? `${trunc(b.title, 40)}: ` : ''}${trunc(b.detail, 100)}`);
      }
      printSources(r);
    });
  },
  async signals(o, a) {
    const s = o.signals(Number(a.flags.limit ?? 20) || 20);
    emit(a, s, () => (s.length ? printSignals(s, 50) : out('No signals yet. Run `oculon radar`.')));
  },
  async dossier(o, a) {
    const r = await o.dossier(need(a, 1, 'name'), { ...(a.flags['no-github'] ? { github: false } : typeof a.flags.github === 'string' ? { github: a.flags.github } : {}), ...(a.flags.deep ? { deep: true } : {}) });
    emit(a, r, () => {
      const d = r.result;
      out(c.bold(d.wikipedia?.title ?? d.query) + (d.wikipedia?.description ? c.dim(` — ${d.wikipedia.description}`) : ''));
      if (d.wikipedia?.lastDayViews != null) out(`  Wikipedia readers yesterday ${d.wikipedia.lastDayViews.toLocaleString('en-US')}${d.wikipedia.spike ? ` (${d.wikipedia.spike.toFixed(1)}× usual)` : ''}`);
      if (d.sec) out(`  SEC ${d.sec.company.name} (${d.sec.company.ticker}), ${d.sec.filings.length} recent filings`);
      if (d.github) out(`  GitHub ${d.github.owner}: ${d.github.repos.length} new repos`);
      for (const m of d.markets.slice(0, 5)) out(`  ${c.cyan('market')} ${trunc(m.question, 80)} ${c.bold(pct(m.prices[0]))}${m.change1d ? c.dim(` ${m.change1d > 0 ? '+' : ''}${Math.round(m.change1d * 100)}pp 24h`) : ''}`);
      const usd = (n: number) => (n >= 1e9 ? `$${(n / 1e9).toFixed(1)}B` : n >= 1e6 ? `$${(n / 1e6).toFixed(1)}M` : `$${Math.round(n / 1e3)}k`);
      const rec = d.recommendations?.[0];
      if (rec) out(`  analysts ${rec.period}: ${rec.strongBuy + rec.buy} buy · ${rec.hold} hold · ${rec.sell + rec.strongSell} sell`);
      const ins = [...(d.insiderSentiment ?? [])].sort((p, q) => q.month.localeCompare(p.month))[0];
      if (ins) out(`  insider sentiment ${ins.month}: ${ins.mspr >= 0 ? c.green(`+${ins.mspr.toFixed(0)}`) : c.red(ins.mspr.toFixed(0))} ${c.dim('(-100 all selling, +100 all buying)')}`);
      if (d.metrics) out(c.dim(`  P/E ${d.metrics.peTTM?.toFixed(1) ?? '?'} · revenue growth ${d.metrics.revenueGrowthTTMYoy?.toFixed(1) ?? '?'}% · net margin ${d.metrics.netMarginTTM?.toFixed(1) ?? '?'}% · debt/equity ${d.metrics.debtToEquity?.toFixed(2) ?? '?'}`));
      const eps = d.earnings?.[0];
      if (eps?.surprisePct != null) out(`  last earnings ${eps.period}: EPS ${eps.actual} vs ${eps.estimate} est (${eps.surprisePct >= 0 ? '+' : ''}${eps.surprisePct.toFixed(1)}%)`);
      if (d.peers?.length) out(c.dim(`  peers ${d.peers.slice(0, 8).join(', ')}`));
      for (const e of (d.events ?? []).slice(0, 4)) out(`  ${c.yellow('8-K')} ${c.gray(e.date)} ${trunc(e.summary, 100)}${e.officerDeparture ? c.red(` ${e.officerDeparture} leaving`) : ''}`);
      if (d.fda) out(`  FDA recalls: drug ${d.fda.totals.drug ?? 0}, device ${d.fda.totals.device ?? 0}, food ${d.fda.totals.food ?? 0}${d.fda.newClassI.length ? c.red(` · ${d.fda.newClassI.length} new Class I`) : ''}`);
      if (d.trials) out(`  clinical trials: ${d.trials.counts.recruiting} recruiting, ${d.trials.counts.active} active, ${d.trials.counts.terminated} terminated${d.trials.recentlyTerminated.length ? c.yellow(` · ${d.trials.recentlyTerminated.length} stopped recently`) : ''}`);
      if (d.lobbying) out(`  lobbying ${usd(d.lobbying.totalUsd)} over ${d.lobbying.filings} filings`);
      if (d.govContracts) out(`  federal contracts ${d.govContracts.awards} awards, ${usd(d.govContracts.totalUsd)}${d.govContracts.topAgencies[0] ? `, mostly ${d.govContracts.topAgencies[0].agency}` : ''}`);
      if (d.visa) out(`  visa filings ${d.visa.applications}${d.visa.applications >= 500 ? '+' : ''}${d.visa.topTitles[0] ? `, top role ${d.visa.topTitles[0].title}` : ''}`);
      if (d.patents) out(`  patents ${d.patents.count}${d.patents.count >= 250 ? '+' : ''} in the last year${d.patents.latest[0] ? c.dim(`, latest: ${trunc(d.patents.latest[0].title, 70)}`) : ''}`);
      out(c.bold('\nTimeline'));
      for (const t of d.timeline.slice(0, 15)) out(`  ${c.gray(t.date.slice(0, 10))} ${c.cyan(t.source.padEnd(20))} ${trunc(t.text, 95)}`);
      if (!d.timeline.length) out(c.dim('  nothing in the window'));
      if (r.signals.length) {
        out(c.bold('\nSignals'));
        printSignals(r.signals);
      }
      printSources(r);
    });
  },
  async hype(o, a) {
    const r = await o.hype(need(a, 1, 'topic'));
    emit(a, r, () => {
      const d = r.result;
      out(`${c.bold(d.topic)} · ${c.bold(c.yellow(d.phase))}`);
      out(c.dim(d.summary));
      const bars = '▁▂▃▄▅▆▇█';
      for (const ch of d.channels) {
        const max = Math.max(...ch.weekly, 1e-9);
        const spark = ch.weekly.map((v) => bars[Math.min(7, Math.floor((v / max) * 7.99))]).join('');
        out(`  ${ch.channel.padEnd(11)} ${(ch.trend?.phase ?? 'n/a').padEnd(9)} ${c.cyan(spark.padEnd(8))} ${c.dim(`${ch.source}, ${ch.unit}${ch.note ? `; ${ch.note}` : ''}`)}`);
      }
      printSources(r);
    });
  },
  async footprint(o, a) {
    const r = await o.footprint(need(a, 1, 'domain'), {
      ...(a.flags.days ? { days: Number(a.flags.days) } : {}),
      ...(a.flags['no-org'] ? { org: false as const } : typeof a.flags.org === 'string' ? { org: a.flags.org } : {}),
    });
    emit(a, r, () => {
      const d = r.result;
      out(c.bold(`${d.domain} · last ${d.windowDays} days: ${d.counts.subdomain} subdomains, ${d.counts.page} pages, ${d.counts.repo} repos${d.firstScan ? c.dim(' (first scan)') : ''}`));
      for (const f of d.findings.slice(0, 25)) {
        out(`  [${score(f.score)}] ${c.cyan(f.kind.padEnd(9))} ${trunc(f.value, 80)} ${c.gray(f.firstSeen.slice(0, 10))}${f.newSinceLastScan ? c.green(' NEW') : ''}`);
        if (f.reasons.length) out(c.dim(`        ${trunc(f.reasons.join('; '), 110)}`));
      }
      if (!d.findings.length) out(c.dim('  nothing new in the window'));
      printSources(r);
    });
  },
  async plane(o, a) {
    const r = await o.aircraft(need(a, 1, 'registration or hex'));
    emit(a, r, () => {
      const t = r.result;
      out(c.bold(`${t.info?.registration ?? t.query}${t.hex ? c.dim(` (hex ${t.hex})`) : c.dim(' (not found)')}`));
      if (t.info) out(`  ${[t.info.manufacturer, t.info.type].filter(Boolean).join(' ')}${t.info.owner ? `, owner ${c.bold(t.info.owner)}` : ''}`);
      out(`  status ${c.bold(t.status)}${t.state?.altFt != null && t.status === 'AIRBORNE' ? ` at ${t.state.altFt} ft, ${t.state.speedKt ?? '?'} kt` : ''}${t.state?.callsign ? `, callsign ${t.state.callsign}` : ''}`);
      if (t.place) out(`  ${t.place.relation} ${t.place.airport} (${t.place.km} km)`);
      if (t.previous) out(c.dim(`  previous check ${t.previous.at.slice(0, 16)}: ${t.previous.status}${t.previous.place ? ` ${t.previous.place.relation} ${t.previous.place.airport}` : ''}`));
      if (t.change) out(c.yellow(`  ${t.change}`));
      printSources(r);
    });
  },
  async mil(o, a) {
    const r = await o.military();
    emit(a, r, () => {
      const d = r.result;
      out(c.bold(`Military air · ${d.withPosition} aircraft with position (${d.total} flagged)`) + (d.firstRuns ? c.dim('  baseline still building') : ''));
      for (const g of d.regions.slice(0, 15)) {
        out(`  ${String(g.count).padStart(3)}  ${g.label}${g.baselineMedian !== null ? c.dim(` (usual ~${g.baselineMedian})`) : ''}${g.notable.length ? `  ${c.red(g.notable.map((n) => `${n.type}/${n.role}`).join(', '))}` : ''}`);
      }
      if (r.signals.length) {
        out(c.bold('\nSignals'));
        printSignals(r.signals);
      }
      printSources(r);
    });
  },
  async events(o, a) {
    const r = await o.naturalEvents(Number(a.flags.days ?? 7) || 7);
    emit(a, r, () => {
      out(c.bold(`Natural events · ${r.result.events.length} open (NASA EONET)`));
      for (const e of r.result.events.slice(0, 20)) out(`  ${e.severity !== null ? `[${score(e.severity)}]` : '     '} ${c.cyan(e.category.padEnd(13))} ${e.title}${e.why ? c.dim(`  ${e.why}`) : ''}`);
      printSources(r);
    });
  },
  async lights(o, a) {
    const r = await o.nightLights(need(a, 1, 'place'));
    emit(a, r, () => {
      const l = r.result;
      const col = l.verdict === 'DROP' ? c.red : l.verdict === 'RISE' ? c.yellow : c.green;
      out(`${c.bold(l.place.name)}\n  night lights ${col(c.bold(l.verdict))}${l.ratio ? ` (${l.ratio >= 1 ? '+' : ''}${Math.round((l.ratio - 1) * 100)}%)` : ''} · ${l.recent.length} recent nights vs ${l.baseline.length} baseline · newest ${l.latestDate ?? 'n/a'}`);
      out(c.dim(`  recent   ${l.recent.map((d) => d.mean.toFixed(0)).join(' ')}`));
      out(c.dim(`  baseline ${l.baseline.map((d) => d.mean.toFixed(0)).join(' ')}`));
      if (l.alternatives.length) out(c.dim(`  other matches: ${l.alternatives.slice(0, 3).join(' | ')}`));
      printSources(r);
    });
  },
  async image(o, a) {
    const r = await o.satelliteImage(need(a, 1, 'place'), typeof a.flags.date === 'string' ? a.flags.date : undefined);
    let file = r.result.file;
    if (file && typeof a.flags.out === 'string') {
      const dest = resolve(a.flags.out);
      mkdirSync(dirname(dest), { recursive: true });
      copyFileSync(file, dest);
      file = dest;
    }
    emit(a, { ...r.result, file }, () => out(file ? `${c.bold(r.result.place.name)} · ${r.result.date}\n  saved ${file}` : `No image for ${r.result.place.name} on ${r.result.date}.`));
  },
  async ask(o, a) {
    const question = need(a, 1, 'question');
    if (!json(a)) out(c.dim(`thinking about: ${question}`));
    const r = await o.ask(question, { onStep: json(a) ? () => {} : (s) => out(c.dim(`  → ${trunc(s, 120)}`)) });
    emit(a, r, () => {
      out(`\n${r.answer}\n`);
      out(c.dim(`${r.steps.length} tool call(s) · model: ${[...new Set(r.providers)].join(', ')} · AI-written from the tool results above; check the cited sources`));
    });
  },
  async wallet(o, a) {
    const r = await o.wallet(need(a, 1, 'address'));
    emit(a, r, () => {
      const w = r.result;
      out(c.bold(`${w.address} · ${w.kind}`) + (w.knownAs ? `  ${c.cyan(w.knownAs)}` : ''));
      if (w.solana) out(`  ${w.solana.sol.toFixed(3)} SOL, ${w.solana.tokens} token accounts`);
      if (w.portfolio) {
        out(`  portfolio ${c.bold(`$${Math.round(w.portfolio.totalUsd).toLocaleString('en-US')}`)}${w.portfolio.change1dPct != null ? c.dim(` (${w.portfolio.change1dPct >= 0 ? '+' : ''}${w.portfolio.change1dPct.toFixed(1)}% 24h)`) : ''}`);
        for (const t of w.portfolio.top.slice(0, 6)) out(`    ${t.symbol.padEnd(10)} $${Math.round(t.valueUsd).toLocaleString('en-US').padStart(12)} ${c.dim(t.chain)}`);
        out(c.dim('    values as reported by Zerion; airdropped tokens can carry inflated prices'));
      }
      if (w.firstSeen) out(`  first transaction ${w.firstSeen.slice(0, 10)} (${w.ageDays} days ago) · ${w.recentTxs.length} recent txs`);
      if (w.robinhood) out(`  Robinhood Chain: ${w.robinhood.balanceEth.toFixed(4)} ETH, ${w.robinhood.txCount} txs${w.robinhood.isContract ? ', contract' : ''}`);
      if (w.counterparties.length) out(`  known counterparties: ${w.counterparties.slice(0, 5).map((x) => `${x.knownAs} ×${x.txs}`).join(c.dim(' · '))}`);
      out(`  risk: ${w.labels.length ? c.red(w.labels.join(', ')) : c.green('no GoPlus labels')}${w.riskScore != null ? ` · Webacy ${w.riskScore}` : ''}${w.riskIssues.length ? c.dim(` (${w.riskIssues.slice(0, 4).join(', ')})`) : ''}`);
      printSources(r);
    });
  },
  async ships(o, a) {
    const secs = Number(a.flags.seconds ?? 30) || 30;
    if (!json(a)) out(c.dim(`listening to AIS for ${secs}s…`));
    const r = await o.ships(need(a, 1, 'place'), secs);
    emit(a, r, () => {
      const d = r.result;
      out(`${c.bold(d.place.name)} · ${d.total} vessels in ${d.seconds}s · ${d.moving} moving · ${d.stationary} anchored/moored${d.baselineStationary !== null ? c.dim(` (usual ~${d.baselineStationary})`) : ''}`);
      if (Object.keys(d.byType).length) out(c.dim(`  types: ${Object.entries(d.byType).sort((x, y) => y[1] - x[1]).map(([t, n]) => `${t} ${n}`).join(', ')}`));
      for (const v of d.vessels.filter((x) => x.name).slice(0, 20)) out(`  ${trunc(v.name ?? '', 24).padEnd(24)} ${String(v.mmsi).padEnd(10)} ${v.sog != null ? `${v.sog.toFixed(1)} kn`.padStart(8) : '       ?'}  ${v.stationary ? c.yellow('stationary') : c.green('moving    ')}  ${c.dim(v.type)}${v.destination ? c.dim(` → ${v.destination}`) : ''}`);
      if (r.signals.length) printSignals(r.signals);
      printSources(r);
    });
  },
  async ship(o, a) {
    const secs = Number(a.flags.seconds ?? 60) || 60;
    if (!json(a)) out(c.dim(`following MMSI ${a.pos[1] ?? '?'} for up to ${secs}s…`));
    const r = await o.ship(need(a, 1, 'MMSI'), secs);
    emit(a, r, () => {
      const v = r.result.vessel;
      if (!v) return out(`No report from MMSI ${r.result.mmsi} in ${r.result.seconds}s. ${c.dim(r.provenance[0]?.note ?? '')}`);
      out(`${c.bold(v.name ?? String(v.mmsi))} · ${v.type} · ${v.sog ?? '?'} kn · ${v.lat.toFixed(4)}, ${v.lon.toFixed(4)} at ${v.lastSeen.slice(0, 16)}Z${v.destination ? ` · → ${v.destination}` : ''}`);
      out(c.dim(`  https://www.marinetraffic.com/en/ais/details/ships/mmsi:${v.mmsi}`));
    });
  },
  async deployer(o, a) {
    const r = await o.robinhoodDeployer(need(a, 1, 'token or deployer address'));
    emit(a, r, () => {
      const d = r.result;
      const col = d.verdict === 'DANGER' ? c.red : d.verdict === 'CAUTION' ? c.yellow : d.verdict === 'OK' ? c.green : c.gray;
      out(`${c.bold(`Deployer ${d.deployer}`)} · ${col(c.bold(d.verdict))}`);
      out(`  ${d.reasons.join('; ')} · ${d.contracts} contract(s) launched`);
      for (const t of d.tokens.slice(0, 15)) out(`  ${(t.symbol ?? '?').padEnd(12)} ${t.address}  liq $${t.reserveUsd.toLocaleString('en-US').padStart(10)}  ${t.dead ? c.red('dead') : c.green('alive')}  ${c.dim(t.createdAt.slice(0, 10))}`);
      printSources(r);
    });
  },
  async rh(o, a) {
    const r = await o.robinhood();
    emit(a, r, () => {
      const s = r.result.stats;
      out(c.bold('Robinhood Chain') + (s ? c.dim(` · ${s.transactionsToday.toLocaleString('en-US')} txs today · ${s.addresses.toLocaleString('en-US')} addresses · gas ${s.gasAverage ?? '?'} gwei`) : ''));
      out(c.bold('\nTrending pools'));
      for (const t of r.result.trending.slice(0, 10))
        out(`  ${trunc(t.pool.name, 26).padEnd(26)} liq $${Math.round(t.pool.liquidityUsd).toLocaleString('en-US').padStart(10)}  24h ${String(t.pool.change24h?.toFixed(0) ?? '?').padStart(5)}%${t.flags.length ? `  ${c.yellow(t.flags.join('; '))}` : ''}`);
      out(c.bold('\nNew pools'));
      for (const f of r.result.fresh.slice(0, 12))
        out(`  ${trunc(f.pool.name, 26).padEnd(26)} ${f.ageHours.toFixed(1).padStart(5)}h  liq $${Math.round(f.pool.liquidityUsd).toLocaleString('en-US').padStart(9)}  buys/sells ${f.pool.buys24h}/${f.pool.sells24h}${f.flags.length ? `  ${c.red(f.flags.join('; '))}` : ''}`);
      if (r.signals.length) {
        out(c.bold('\nSignals'));
        printSignals(r.signals);
      }
      printSources(r);
    });
  },
  async token(o, a) {
    if (a.flags.chain === 'robinhood') {
      const r = await o.robinhoodToken(need(a, 1, 'token address').split(' ')[0]!);
      return emit(a, r, () => {
        const t = r.result;
        const col = t.verdict === 'DANGER' ? c.red : t.verdict === 'CAUTION' ? c.yellow : t.verdict === 'OK' ? c.green : c.gray;
        out(`${c.bold(t.symbol ?? t.address)} on Robinhood Chain · ${col(c.bold(t.verdict))}`);
        out(c.dim(`  holders ${t.holders?.toLocaleString('en-US') ?? '?'} · verified ${t.verified ?? '?'} · top 10 hold ${t.top10Share != null ? `${Math.round(t.top10Share * 100)}%` : '?'}`));
        out(c.dim(`  deployer ${t.deployer.address} · ${t.deployer.otherTokens} other token(s), ${t.deployer.dead} dead`));
        for (const why of t.reasons) out(`  - ${why}`);
        for (const p of t.pools.slice(0, 4)) out(`  ${c.cyan(trunc(p.pool.name, 24).padEnd(24))} liq $${Math.round(p.pool.liquidityUsd).toLocaleString('en-US')} · vol24h $${Math.round(p.pool.volume24h).toLocaleString('en-US')}`);
        printSources(r);
      });
    }
    const r = await o.token(need(a, 1, 'token address').split(' ')[0]!, typeof a.flags.chain === 'string' ? a.flags.chain : 'eth');
    emit(a, r, () => {
      const t = r.result;
      const col = t.verdict === 'DANGER' ? c.red : t.verdict === 'CAUTION' ? c.yellow : t.verdict === 'OK' ? c.green : c.gray;
      out(`${c.bold(t.security?.symbol || t.market?.symbol?.toUpperCase() || t.address)} on ${t.chain} · ${col(c.bold(t.verdict))}`);
      for (const why of t.reasons) out(`  - ${why}`);
      if (t.market) out(`  price $${t.market.priceUsd ?? '?'} · mcap ${t.market.marketCapUsd ? `$${Math.round(t.market.marketCapUsd).toLocaleString('en-US')}` : '?'}`);
      if (t.security) out(c.dim(`  holders ${t.security.holders?.toLocaleString('en-US') ?? '?'} · buy tax ${t.security.buyTax ?? '?'} · sell tax ${t.security.sellTax ?? '?'}`));
      for (const p of t.pairs.slice(0, 5)) out(`  ${c.cyan(p.dex.padEnd(12))} ${p.pair.padEnd(14)} liq $${Math.round(p.liquidityUsd ?? 0).toLocaleString('en-US')} · vol24h $${Math.round(p.volume24h ?? 0).toLocaleString('en-US')}`);
      printSources(r);
    });
  },
  async space(o, a) {
    const r = await o.spaceWeather();
    emit(a, r, () => {
      const s = r.result;
      out(`${c.bold('Space weather')} · ${s.stormLevel === 'quiet' ? c.green('quiet') : c.yellow(s.stormLevel)} · Kp now ${s.kpNow ?? '?'}, max 24h ${s.kpMax24h ?? '?'}`);
      if (s.strongestFlare) out(`  strongest flare (7d) ${c.bold(s.strongestFlare.maxClass)} at ${s.strongestFlare.maxTime.slice(0, 16)}Z · ${s.flares7d} flares`);
      if (s.scales) out(`  NOAA scales now R${s.scales.now.r} S${s.scales.now.s} G${s.scales.now.g}${s.scales.days.length ? c.dim(` · next days G ${s.scales.days.map((d) => d.g).join('/')}, R1-R2 odds ${s.scales.days.map((d) => `${d.rMinorProb ?? '?'}%`).join('/')}`) : ''}`);
      if (s.solarWind) out(`  solar wind ${s.solarWind.speedKmS ?? '?'} km/s · Bt ${s.solarWind.bt ?? '?'} nT · Bz ${s.solarWind.bz != null && s.solarWind.bz <= -10 ? c.red(`${s.solarWind.bz}`) : s.solarWind.bz ?? '?'} nT${c.dim(' (strongly negative Bz drives storms)')}`);
      if (s.forecast?.expectedKpMax != null) out(`  3-day forecast: max Kp ${s.forecast.expectedKpMax}${c.dim(` ${Object.entries(s.forecast.kpByDay).map(([d, k]) => `${d} ${k}`).join(', ')}`)}`);
      for (const al of (s.alerts ?? []).slice(0, 6)) out(`  ${al.kind === 'WARNING' || al.kind === 'ALERT' ? c.yellow(al.kind.toLowerCase().padEnd(7)) : c.dim(al.kind.toLowerCase().padEnd(7))} ${c.gray(al.issued.slice(0, 16).replace('T', ' '))} ${trunc(al.title, 90)}${al.scale ? ` ${c.bold(al.scale)}` : ''}`);
      const toEarth = (s.cmes ?? []).filter((x) => x.earthArrival);
      if (s.cmes?.length) out(`  CMEs (7d): ${s.cmes.length}${toEarth.length ? `, ${c.yellow(`${toEarth.length} modelled to reach Earth`)}` : ''}`);
      for (const x of toEarth.slice(0, 4)) out(`    ${c.gray(x.start.slice(0, 16).replace('T', ' '))} ${x.speedKmS ?? '?'} km/s → arrives ${x.earthArrival!.slice(0, 16).replace('T', ' ')}${x.earthGlancing ? ' (glancing)' : ''}${x.kpPredicted ? `, model Kp ${x.kpPredicted}` : ''}`);
      const neo = (s as { neo?: { name: string; time: string; missLunar: number; diameterM: { max: number }; hazardous: boolean }[] }).neo ?? [];
      if (neo[0]) out(`  closest asteroid pass: ${neo[0].name} ${neo[0].missLunar.toFixed(1)} lunar distances on ${neo[0].time} UTC, up to ${Math.round(neo[0].diameterM.max)} m${neo[0].hazardous ? c.yellow(' (potentially hazardous)') : ''}`);
      if (r.signals.length) printSignals(r.signals);
      printSources(r);
    });
  },
  async air(o, a) {
    const r = await o.airQuality(need(a, 1, 'place'));
    emit(a, r, () => {
      const d = r.result;
      out(`${c.bold(d.place.name)}\n  PM2.5 median ${d.median != null ? c.bold(`${d.median.toFixed(0)} µg/m³`) : 'n/a'} · ${d.category ?? 'no fresh stations within 25 km'}`);
      for (const s of d.stations) out(`    ${trunc(s.name, 40).padEnd(40)} ${String(s.value).padStart(6)} ${s.unit}  ${c.dim(`${s.category}, ${s.time.slice(0, 16)}Z`)}`);
      printSources(r);
    });
  },
  async url(o, a) {
    const r = await o.urlCheck(need(a, 1, 'link'));
    emit(a, r, () => {
      const d = r.result;
      const tone = d.verdict === 'malicious' ? c.red : d.verdict === 'suspicious' ? c.yellow : c.green;
      out(`${c.bold(d.host)}  ${tone(d.verdict.toUpperCase())}  ${c.dim(`risk ${d.risk}/100`)}`);
      for (const x of d.reasons) out(`  - ${x}`);
      if (d.domainInfo?.registered) out(c.dim(`  domain ${d.domain}: registered ${d.domainInfo.registered.slice(0, 10)}${d.domainInfo.registrar ? ` via ${d.domainInfo.registrar}` : ''}${d.domainInfo.expires ? `, expires ${d.domainInfo.expires.slice(0, 10)}` : ''}`));
      if (d.scans?.count) out(c.dim(`  urlscan.io: ${d.scans.count} scan(s) since ${d.scans.firstSeen?.slice(0, 10)}${d.scans.countries.length ? `, hosted in ${d.scans.countries.join(', ')}` : ''}${d.scans.latest ? `  ${d.scans.latest}` : ''}`));
      if (d.verdict === 'no known threats') out(c.dim('  no source flags it; that is not a guarantee the page is safe'));
      printSources(r);
    });
  },
  async audit(o, a) {
    const args = a.pos.slice(1);
    let text: string;
    if (!args.length) {
      const guess = ['package.json', 'requirements.txt'].find((f) => existsSync(f));
      if (!guess) throw new UsageError('usage: oculon audit <package.json|requirements.txt> | oculon audit npm:express@4.17.1 pypi:requests');
      text = readFileSync(guess, 'utf8');
    } else if (args.length === 1 && existsSync(args[0]!)) text = readFileSync(args[0]!, 'utf8');
    else text = args.map((x) => (x.includes(':') ? x : `npm:${x}`)).join(' ');
    if (!json(a)) out(c.dim('checking packages on deps.dev…'));
    const r = await o.audit(text, a.flags.max ? { max: Number(a.flags.max) } : {});
    emit(a, r, () => {
      const s = r.result.summary;
      out(`${c.bold(`${r.result.manifest}: ${s.checked} of ${s.total} packages checked`)}  ${s.vulnerable ? c.red(`${s.vulnerable} vulnerable (${s.advisories} advisories)`) : c.green('no known vulnerabilities')}${s.deprecated ? `  ${c.yellow(`${s.deprecated} deprecated`)}` : ''}${s.stale ? `  ${s.stale} stale` : ''}`);
      for (const p of r.result.packages) {
        if (!p.flags.length && !a.flags.all) continue;
        const tone = p.risk >= 60 ? c.red : p.risk >= 30 ? c.yellow : (x: string) => x;
        out(`  ${tone(String(p.risk).padStart(3))}  ${c.bold(`${p.name}@${p.version ?? '?'}`)}${p.dev ? c.dim(' (dev)') : ''}${p.project?.scorecard != null ? c.dim(`  scorecard ${p.project.scorecard}`) : ''}`);
        for (const f of p.flags) out(`         - ${f}`);
        for (const x of p.advisories.slice(0, 3)) out(c.dim(`           ${x.aliases[0] ?? x.id}${x.cvss ? ` CVSS ${x.cvss}` : ''}: ${trunc(x.title, 90)}`));
      }
      const clean = r.result.packages.filter((p) => !p.flags.length).length;
      if (clean && !a.flags.all) out(c.dim(`  ${clean} package(s) with no flags (show them with --all)`));
      for (const x of r.result.skipped) out(c.dim(`  skipped ${x}`));
      printSources(r);
    });
  },
  async factcheck(o, a) {
    const claim = a.pos.slice(1).join(' ').trim();
    if (!claim) throw new UsageError('usage: oculon factcheck "<claim>" | oculon factcheck <news url>');
    const r = await o.factCheck(claim);
    emit(a, r, () => {
      const d = r.result;
      const tone = /false|misleading/.test(d.verdict) ? c.red : /true/.test(d.verdict) ? c.green : c.yellow;
      out(`${c.bold(trunc(d.claim, 160))}\n  ${tone(d.verdict.toUpperCase())}${d.confidence ? c.dim(`  confidence ${d.confidence}%`) : ''}  ${c.dim(d.method)}`);
      if (d.summary) out(`  ${d.summary}`);
      for (const e of [...d.factChecks, ...d.web].filter((e) => !d.cited.length || d.cited.includes(e.n)).slice(0, 8)) out(`  [${e.n}] ${e.kind === 'fact-check' ? c.bold(e.publisher) : e.publisher}${e.rating ? ` "${e.rating}"` : ''}: ${trunc(e.title, 90)}\n      ${c.cyan(e.url)}`);
      printSources(r);
    });
  },
  async travel(o, a) {
    const r = await o.travel(a.pos.slice(1).join(' ') || need(a, 1, 'place'));
    emit(a, r, () => {
      const d = r.result;
      const tone = d.level === 'severe' || d.level === 'high' ? c.red : d.level === 'moderate' ? c.yellow : c.green;
      out(`${c.bold(d.place.name)}\n  ${tone(`${d.level.toUpperCase()} risk`)}`);
      for (const p of d.points) out(`  - ${p}`);
      if (d.weather) out(c.dim(`  next days: ${d.weather.days.slice(0, 5).map((x) => `${x.date.slice(5)} ${x.summary} ${Math.round(x.tMin)}–${Math.round(x.tMax)}°C`).join(' · ')}`));
      if (d.air?.pm25 != null) out(c.dim(`  air: PM2.5 ${d.air.pm25.toFixed(0)} µg/m³ (${d.air.category})`));
      if (d.advisories.us) out(c.dim(`  ${d.advisories.us.url}`));
      if (d.advisories.uk) out(c.dim(`  ${d.advisories.uk.url}`));
      printSources(r);
    });
  },
  async scam(o, a) {
    let msg = a.pos.slice(1).join(' ').trim();
    if (!msg && !process.stdin.isTTY) msg = readFileSync(0, 'utf8');
    if (!msg) throw new UsageError('usage: oculon scam "<message text>"   (or pipe the message in)');
    const r = await o.scamCheck(msg);
    emit(a, r, () => {
      const d = r.result;
      const tone = d.verdict === 'likely scam' ? c.red : d.verdict === 'suspicious' ? c.yellow : c.green;
      out(`${tone(d.verdict.toUpperCase())}  ${c.dim(`risk ${d.risk}/100`)}`);
      if (d.explanation) out(`  ${d.explanation}`);
      for (const x of d.reasons) out(`  - ${x}`);
      for (const l of d.links) out(c.dim(`  link ${l.url}: ${l.verdict} (${l.risk})`));
      for (const x of d.advice) out(`  → ${x}`);
      printSources(r);
    });
  },
  async recall(o, a) {
    const q = a.pos.slice(1).join(' ').trim();
    if (!q) throw new UsageError('usage: oculon recall <VIN | "2018 Honda Accord" | product name>');
    const r = await o.recall(q);
    emit(a, r, () => {
      const d = r.result;
      const head = d.vehicle ? `${d.vehicle.year} ${d.vehicle.make} ${d.vehicle.model}${d.vehicle.vin ? c.dim(` (VIN ${d.vehicle.vin})`) : ''}` : d.query;
      out(`${c.bold(head)}  ${d.recalls.length ? c.yellow(`${d.recalls.length} recall(s)`) : c.green('no recalls found')}`);
      for (const x of d.recalls.slice(0, 12)) {
        const warn = x.parkIt ? c.red(' DO NOT DRIVE') : x.parkOutside ? c.red(' PARK OUTSIDE') : x.classification === 'Class I' ? c.red(' Class I') : '';
        out(`  ${c.dim(x.date ?? '')} ${x.source} ${x.id}${warn}\n    ${trunc(x.title, 110)}\n    ${c.dim(trunc(x.hazard, 160))}\n    ${c.cyan(x.url)}`);
      }
      if (d.note) out(c.dim(`  ${d.note}`));
      printSources(r);
    });
  },
  async email(o, a) {
    const r = await o.emailSecurity(need(a, 1, 'domain'));
    emit(a, r, () => {
      const d = r.result;
      const tone = d.verdict === 'protected' ? c.green : d.verdict === 'partly protected' ? c.yellow : c.red;
      out(`${c.bold(d.domain)}  ${tone(d.verdict.toUpperCase())}  ${c.dim(`score ${d.score}/100`)}`);
      out(`  SPF    ${d.spf.record ? `${d.spf.all ?? 'no all'} · ${d.spf.lookups} lookups` : c.red('missing')}`);
      out(`  DMARC  ${d.dmarc.record ? `p=${d.dmarc.policy}${d.dmarc.pct != null ? ` pct=${d.dmarc.pct}` : ''}${d.dmarc.reports ? ' · reports on' : ''}` : c.red('missing')}`);
      out(`  DKIM   ${d.dkim.selectorsFound.length ? d.dkim.selectorsFound.join(', ') : c.dim('no common selector found')}`);
      out(`  extra  MTA-STS ${d.mtaSts.mode ?? 'off'} · TLS-RPT ${d.tlsRpt ? 'on' : 'off'} · DNSSEC ${d.dnssec ? 'on' : 'off'} · CAA ${d.caa.length ? 'set' : 'none'} · MX ${d.mx.length ? d.mx.slice(0, 2).join(', ') : 'none'}`);
      if (d.fixes.length) out(`\n${c.bold('Fixes')}`);
      d.fixes.forEach((f, i) => out(`  ${i + 1}. ${f}`));
      printSources(r);
    });
  },
  async ip(o, a) {
    const q = a.pos[1]?.trim();
    if (!q) throw new UsageError('usage: oculon ip <IP address | domain>');
    const r = await o.ipCheck(q);
    emit(a, r, () => {
      const d = r.result;
      const tone = d.verdict === 'malicious' ? c.red : d.verdict === 'suspicious' ? c.yellow : c.green;
      out(`${c.bold(d.ip)}${d.resolvedFrom ? c.dim(` (${d.resolvedFrom})`) : ''}  ${tone(d.verdict.toUpperCase())}  ${c.dim(`risk ${d.risk}/100`)}`);
      const where = d.location ? [d.location.city, d.location.region, d.location.country].filter(Boolean).join(', ') : 'unknown';
      out(`  network  ${[d.network.asn, d.network.name].filter(Boolean).join(' ') || 'unknown'}${d.network.type ? c.dim(` · ${d.network.type}`) : ''}`);
      out(`  where    ${where}${d.network.reverse ? c.dim(` · ${d.network.reverse}`) : ''}`);
      const fl = Object.entries(d.flags).filter(([, v]) => v).map(([k]) => k);
      if (fl.length) out(`  flags    ${fl.join(', ')}`);
      if (d.ports?.ports.length) out(`  ports    ${d.ports.ports.slice(0, 12).join(', ')}${d.ports.vulns.length ? c.yellow(` · ${d.ports.vulns.length} known CVEs`) : ''}`);
      for (const x of d.reasons) out(`  - ${x}`);
      for (const x of d.advice) out(`  → ${x}`);
      printSources(r);
    });
  },
  async hash(o, a) {
    const q = a.pos[1]?.trim();
    if (!q) throw new UsageError('usage: oculon hash <MD5 | SHA-1 | SHA-256>');
    const r = await o.hashCheck(q);
    emit(a, r, () => {
      const d = r.result;
      const tone = d.verdict === 'malicious' ? c.red : d.verdict === 'suspicious' ? c.yellow : d.verdict === 'known good' ? c.green : c.gray;
      out(`${tone(d.verdict.toUpperCase())}  ${c.dim(`${d.algorithm} ${d.hash}`)}`);
      if (d.name || d.family) out(`  ${[d.name, d.family && `family ${d.family}`].filter(Boolean).join(' · ')}`);
      for (const x of d.reasons) out(`  - ${x}`);
      if (d.bazaar) out(c.dim(`  ${d.bazaar.link}`));
      if (d.virustotal) out(c.dim(`  ${d.virustotal.link}`));
      for (const x of d.advice) out(`  → ${x}`);
      printSources(r);
    });
  },
  async ransomware(o, a) {
    const r = await o.ransomware(a.pos.slice(1).join(' ').trim());
    emit(a, r, () => {
      const d = r.result;
      out(`${c.bold(d.query ? `Ransomware claims: ${d.query}` : 'Newest ransomware claims')}  ${c.dim(`${d.total} found`)}`);
      if (d.byGroup.length) out(c.dim(`  groups   ${d.byGroup.slice(0, 6).map((x) => `${x.name} ${x.count}`).join(' · ')}`));
      if (d.byCountry.length && d.mode !== 'country') out(c.dim(`  countries ${d.byCountry.slice(0, 6).map((x) => `${x.name} ${x.count}`).join(' · ')}`));
      for (const v of d.victims.slice(0, 15)) out(`  ${c.dim((v.discovered ?? v.attacked ?? '').slice(0, 10))} ${c.bold(trunc(v.victim, 60))} ${c.red(v.group)}${v.country ? c.dim(` ${v.country}`) : ''}${v.sector ? c.dim(` · ${v.sector}`) : ''}`);
      out(c.dim(`  ${d.note}`));
      printSources(r);
    });
  },
  async company(o, a) {
    const q = a.pos.slice(1).join(' ').trim();
    if (!q) throw new UsageError('usage: oculon company <name | LEI | EU VAT number>');
    const r = await o.companyCheck(q);
    emit(a, r, () => {
      const d = r.result;
      if (d.vat) out(`${c.bold(`VAT ${d.vat.country}${d.vat.number}`)}  ${d.vat.valid ? c.green('VALID') : c.red('NOT VALID')}${d.vat.name ? `  ${d.vat.name}` : ''}${d.vat.address ? c.dim(`\n  ${d.vat.address}`) : ''}`);
      for (const x of d.records.slice(0, 6)) {
        out(`${c.bold(x.name)}  ${c.dim(x.lei)}  ${x.status === 'ACTIVE' ? c.green(x.status) : c.yellow(x.status ?? '?')} ${x.registration === 'ISSUED' ? c.dim('LEI issued') : c.yellow(`LEI ${(x.registration ?? '?').toLowerCase()}`)}`);
        out(c.dim(`  ${[x.address, x.registeredAs && `reg. ${x.registeredAs}`, x.created && `since ${x.created}`].filter(Boolean).join(' · ')}`));
        if (x.parent) out(c.dim(`  ultimate parent ${x.parent.name} (${x.parent.lei})`));
      }
      for (const w of d.warnings) out(c.yellow(`  ! ${w}`));
      printSources(r);
    });
  },
  async password(o, a) {
    let pw = a.pos.slice(1).join(' ');
    if (!pw && !process.stdin.isTTY) pw = readFileSync(0, 'utf8').replace(/\r?\n$/, '');
    if (!pw && process.stdin.isTTY) pw = await readHidden('Password (not shown, not stored): ');
    if (!pw) throw new UsageError('usage: oculon password   (asks without echo; or pipe it in)');
    const r = await o.passwordCheck(pw);
    emit(a, r, () => {
      const d = r.result;
      out(d.pwned ? c.red(`PWNED  seen ${d.count.toLocaleString('en-US')} times in breaches`) : c.green('NOT FOUND in known breaches'));
      for (const x of d.advice) out(`  → ${x}`);
      out(c.dim('  Only the first 5 characters of the SHA-1 hash were sent (Have I Been Pwned, k-anonymity).'));
    });
  },
  async breaches(o, a) {
    const r = await o.breaches(a.pos.slice(1).join(' ').trim());
    emit(a, r, () => {
      const d = r.result;
      out(c.bold(d.query ? `Breaches: ${d.query}  ${d.total ? c.red(`${d.total} found`) : c.green('none found')}` : 'Newest breaches in Have I Been Pwned'));
      for (const b of d.breaches) out(`  ${c.dim(b.breachDate ?? '')} ${c.bold(b.title)}${b.domain ? c.dim(` ${b.domain}`) : ''}  ${b.accounts.toLocaleString('en-US')} accounts\n    ${c.dim(trunc(b.dataClasses.join(', '), 120))}`);
      out(c.dim(`  ${d.note}`));
      printSources(r);
    });
  },
  async phone(o, a) {
    const q = a.pos.slice(1).join(' ').trim();
    if (!q) throw new UsageError('usage: oculon phone <+number> [--country US]');
    const r = await o.phoneCheck(q, typeof a.flags.country === 'string' ? { country: a.flags.country } : {});
    emit(a, r, () => {
      const d = r.result;
      const tone = d.risk === 'high' ? c.red : d.risk === 'medium' ? c.yellow : c.green;
      out(`${c.bold(d.e164)}  ${tone(`${d.risk.toUpperCase()} RISK`)}${d.valid === false ? c.red('  not valid') : ''}`);
      out(`  ${[d.country, d.location, d.lineType, d.carrier].filter(Boolean).join(' · ')}`);
      for (const w of d.warnings) out(c.yellow(`  ! ${w}`));
      for (const x of d.advice) out(`  → ${x}`);
      printSources(r);
    });
  },
  async satellite(o, a) {
    const r = await o.satellites(a.pos.slice(1).join(' ').trim());
    emit(a, r, () => {
      const d = r.result;
      if (d.mode === 'recent') {
        out(`${c.bold('Launched in the last 30 days')}  ${c.dim(`${d.total} objects`)}`);
        for (const l of d.launches.slice(0, 20)) out(`  ${c.dim(l.id)} ${l.names.join(', ')} ${c.dim(`(${l.objects})`)}`);
      } else {
        if (!d.objects.length) out(c.yellow(`  ${d.note}`));
        for (const x of d.objects) {
          out(`${c.bold(x.name)}  ${c.dim(`NORAD ${x.norad} · ${x.intlId}`)}${x.status ? `  ${x.status}` : ''}`);
          if (x.orbit) out(`  ${x.orbit.regime} ${x.orbit.perigeeKm}-${x.orbit.apogeeKm} km · ${x.orbit.periodMin} min · ${x.orbit.inclination}°`);
          const meta = [x.owner && `owner ${x.owner}`, x.type, x.launchDate && `launched ${x.launchDate}`, x.decayed && `decayed ${x.decayed}`].filter(Boolean);
          if (meta.length) out(c.dim(`  ${meta.join(' · ')}`));
        }
      }
      printSources(r);
    });
  },
  async papers(o, a) {
    const topic = a.pos.slice(1).join(' ').trim();
    if (!topic) throw new UsageError('usage: oculon papers "<topic>" [--years 3]');
    const r = await o.papers(topic, a.flags.years ? { years: Number(a.flags.years) } : {});
    emit(a, r, () => {
      const d = r.result;
      out(`${c.bold(d.topic)}  ${c.dim(`${(d.totalWorks ?? 0).toLocaleString('en-US')} works${d.trend ? ` · field ${d.trend}` : ''}`)}`);
      if (d.perYear.length) out(c.dim(`  per year: ${d.perYear.map((x) => `${x.year} ${x.count.toLocaleString('en-US')}`).join(' · ')}`));
      if (d.overview) out(`\n${d.overview}\n`);
      const line = (p: (typeof d.mostCited)[number]) => `  [${p.n}] ${c.bold(trunc(p.title, 100))}\n      ${c.dim(`${p.year ?? '?'} · ${p.venue ?? 'n/a'} · ${p.citations} citations`)}${p.tldr ? `\n      ${trunc(p.tldr, 160)}` : ''}\n      ${c.cyan(p.openAccessUrl ?? p.url)}`;
      if (d.mostCited.length) out(c.bold('Most cited'));
      d.mostCited.slice(0, 6).forEach((p) => out(line(p)));
      if (d.newest.length) out(c.bold('Newest'));
      d.newest.slice(0, 4).forEach((p) => out(line(p)));
      if (d.pubmed?.papers.length) { out(c.bold(`PubMed (${d.pubmed.count.toLocaleString('en-US')} in 2 years)`)); d.pubmed.papers.slice(0, 4).forEach((p) => out(line(p))); }
      printSources(r);
    });
  },
  async country(o, a) {
    const r = await o.country(a.pos.slice(1).join(' ') || need(a, 1, 'country'));
    emit(a, r, () => {
      const d = r.result;
      out(`${c.bold(d.name)}  ${c.dim(`${d.region ?? ''} · ${d.incomeLevel ?? ''} · capital ${d.capital ?? 'n/a'}`)}`);
      out(`  head of state ${d.leaders.headOfState ?? 'n/a'}${d.leaders.headOfGovernment && d.leaders.headOfGovernment !== d.leaders.headOfState ? ` · government ${d.leaders.headOfGovernment}` : ''}`);
      for (const i of d.indicators) if (i.value != null) out(`  ${i.name.padEnd(15)} ${i.unit === 'USD' ? `$${i.value >= 1e9 ? `${(i.value / 1e9).toFixed(1)}B` : Math.round(i.value).toLocaleString('en-US')}` : i.unit === 'people' ? `${(i.value / 1e6).toFixed(1)}M` : `${i.value.toFixed(1)}%`}  ${c.dim(i.year ?? '')}`);
      const yrs = Object.keys(d.outlook.growth);
      if (yrs.length) out(`  IMF outlook    ${yrs.map((y) => `${y}: growth ${d.outlook.growth[y]}%, inflation ${d.outlook.inflation[y] ?? '?'}%`).join(' · ')}`);
      if (d.currency.perUsd) out(`  1 USD = ${d.currency.perUsd.toFixed(2)} ${d.currency.code}`);
      if (d.advisories.us) out(`  US advisory level ${d.advisories.us.level}: ${d.advisories.us.text}`);
      if (d.advisories.uk?.alerts.length) out(`  UK FCDO ${d.advisories.uk.alerts.join('; ')}`);
      for (const x of d.outages) out(c.yellow(`  internet outage: ${x}`));
      for (const h of d.hazards) out(c.yellow(`  ${h.level.toLowerCase()} alert: ${h.type} ${h.name}`));
      if (d.headlines.length) out(c.bold('Headlines'));
      for (const h of d.headlines.slice(0, 5)) out(`  ${trunc(h.title, 110)}  ${c.dim(h.date.slice(0, 10))}`);
      printSources(r);
    });
  },
  async airport(o, a) {
    const r = await o.airport(a.pos.slice(1).join(' ') || need(a, 1, 'airport'));
    emit(a, r, () => {
      const d = r.result;
      const tone = d.verdict === 'normal' ? c.green : d.verdict === 'disrupted' ? c.red : c.yellow;
      out(`${c.bold(d.airport.name)}  ${tone(d.verdict.toUpperCase())}`);
      for (const p of d.points) out(`  - ${p}`);
      if (d.metar) out(c.dim(`  ${d.metar.raw}`));
      if (d.taf) out(c.dim(`  ${trunc(d.taf.raw, 200)}`));
      printSources(r);
    });
  },
  async monitor(o, a) {
    const text = a.pos.slice(1).join(' ').trim();
    if (!text) throw new UsageError('usage: oculon monitor "<what to watch>"   e.g. "internet outages in Iran", "critical CVEs for nginx", "earthquakes above 6 near Tokyo"');
    if (a.flags['dry-run']) {
      const r = await o.monitorParse(text);
      return emit(a, r, () => out(`would watch ${c.bold(r.kind)} ${r.target}: ${r.description} ${c.dim(`(${r.method})`)}`));
    }
    const r = await o.monitor(text);
    emit(a, r, () => out(`${c.green('monitoring')} #${r.item.id} ${r.rule.kind} ${c.bold(r.rule.target)}\n  ${r.rule.description}\n${c.dim('  checked with the watchlist (oculon watch run, or every cycle of serve --watch / telegram); the first check records a baseline')}`));
  },
  async search(o, a) {
    const r = await o.webSearch(need(a, 1, 'query'), Number(a.flags.max ?? 8) || 8);
    emit(a, r, () => {
      for (const x of r.data ?? []) out(`  ${c.bold(trunc(x.title, 90))}\n    ${c.cyan(x.url)}${x.date ? c.dim(`  ${x.date.slice(0, 16)}`) : ''}\n    ${c.dim(trunc(x.snippet.replace(/\s+/g, ' '), 160))}`);
      if (!r.data) out(`${r.prov.source}: ${r.prov.status} ${r.prov.note ?? ''}`);
    });
  },
  async read(o, a) {
    const r = await o.readPage(need(a, 1, 'url'));
    emit(a, r, () => out(r.data ?? `${r.prov.source}: ${r.prov.status} ${r.prov.note ?? ''}`));
  },
  async narratives(o, a) {
    if (a.pos[1] === 'run') {
      if (!json(a)) out(c.dim('grouping new headlines into narratives…'));
      const r = await o.narrativesRun();
      if (json(a)) return out(JSON.stringify(r, null, 2));
      out(c.dim(`  ${r.result.added} headline(s) assigned, ${r.result.created.length} new narrative(s)`));
      for (const p of r.provenance.filter((x) => x.status === 'ERROR')) out(c.yellow(`  ${p.note}`));
    }
    const list = await o.narratives(14);
    emit(a, list, () => {
      if (!list.length) return out('No narratives yet. Run: oculon narratives run');
      const bars = '▁▂▃▄▅▆▇█';
      out(c.bold('Narratives · stories per day, last 7 days'));
      for (const n of list.slice(0, 20)) {
        const max = Math.max(...n.daily, 1);
        out(`  ${c.cyan(n.daily.map((v) => bars[Math.min(7, Math.floor((v / max) * 7.99))]).join(''))} ${String(n.total).padStart(3)}  ${c.bold(trunc(n.name, 50))} ${c.dim(n.phase.toLowerCase())}`);
        if (n.latest[0]) out(c.dim(`             ${trunc(n.latest[0].title, 100)}`));
      }
    });
  },
  async health(o, a) {
    const r = await o.health(need(a, 1, 'company'));
    emit(a, r, () => {
      const d = r.result;
      const col = d.score >= 60 ? c.green : d.score >= 40 ? c.yellow : c.red;
      out(`${c.bold(d.company)} health ${col(c.bold(`${d.score}/100`))}${d.change !== null ? c.dim(` (${d.change >= 0 ? '+' : ''}${d.change} vs 7-day average)`) : ''}`);
      for (const p of d.parts) out(`  ${(p.points > 0 ? c.green : p.points < 0 ? c.red : c.dim)(String(p.points > 0 ? `+${p.points}` : p.points).padStart(4))}  ${p.name.padEnd(10)} ${c.dim(p.why)}`);
      if (d.history.length > 1) out(c.dim(`  history: ${d.history.map((h) => h.score).join(' → ')}`));
    });
  },
  async impact(o, a) {
    const place = a.pos.slice(1).join(' ').trim();
    const r = await o.impact(place || undefined, Number(a.flags.radius ?? 50) || 50);
    emit(a, r, () => {
      if (!r.result.impacts.length) return out('No M6+ earthquakes or severe storms right now. Name a place to estimate exposure: oculon impact Tokyo --radius 50');
      for (const i of r.result.impacts) {
        out(`${c.bold(i.event)} ${c.dim(`· ${i.radiusKm} km radius · ${i.when.slice(0, 16)}Z`)}`);
        out(`  people in listed settlements: ${c.bold(i.exposedPopulation.toLocaleString('en-US'))}${i.settlements.length ? '' : c.dim('  (no populated places found: likely open sea or remote area)')}`);
        for (const s of i.settlements.slice(0, 6)) out(c.dim(`    ${s.name.padEnd(28)} ${s.population.toLocaleString('en-US').padStart(12)}  ${s.distanceKm} km`));
        if (i.lights) out(`  night lights: ${i.lights.verdict}${i.lights.ratio ? ` (${Math.round((i.lights.ratio - 1) * 100)}%)` : ''} ${c.dim(i.lights.note)}`);
      }
      out(c.dim('\nExposure estimate from Wikidata settlement populations (places can overlap); not a casualty estimate.'));
      printSources(r);
    });
  },
  async contradictions(o, a) {
    if (!json(a)) out(c.dim('reading independent sources and comparing their claims…'));
    const r = await o.contradictions(need(a, 1, 'topic'));
    emit(a, r, () => {
      const d = r.result;
      out(c.bold(`${d.topic} · ${d.sourcesRead.length} sources read · ${d.contradictions.length} contradiction(s)`));
      for (const x of d.contradictions) {
        out(`  ${(x.severity === 'major' ? c.red : c.yellow)(x.severity.padEnd(5))} ${c.bold(x.about)}`);
        out(`        A: ${trunc(x.claimA, 140)} ${c.dim(x.sourceA)}`);
        out(`        B: ${trunc(x.claimB, 140)} ${c.dim(x.sourceB)}`);
      }
      if (!d.contradictions.length) out(c.dim('  the sources agree on the facts they share'));
      out(c.dim(`  read: ${d.sourcesRead.map((s) => new URL(s.url).hostname.replace(/^www\./, '')).join(', ')}`));
    });
  },
  async report(o, a) {
    const r = await o.report(Number(a.flags.days ?? 7) || 7, typeof a.flags.out === 'string' ? resolve(a.flags.out) : undefined);
    emit(a, { file: r.file, counts: r.counts }, () => out(`${c.bold('Report written')} ${r.file}\n${c.dim(`  ${r.counts.signals} signals, ${r.counts.narratives} narratives, ${r.counts.cases} case files. Open it in a browser.`)}`));
  },
  async plugin(o, a) {
    if (a.pos[1] === 'run') {
      const ref = need(a, 2, 'plugin.tool');
      let args: Record<string, unknown> = {};
      if (typeof a.flags.args === 'string') {
        try {
          args = JSON.parse(a.flags.args) as Record<string, unknown>;
        } catch {
          throw new UsageError('--args must be JSON');
        }
      }
      const r = await o.pluginRun(ref.split(' ')[0]!, args);
      return out(JSON.stringify(r, null, 2));
    }
    const { plugins, errors } = await o.plugins();
    const { pluginDir } = await import('../plugins.js');
    emit(a, { dir: pluginDir(), plugins: plugins.map((p) => ({ name: p.name, description: p.description, tools: p.tools.map((t) => t.name) })), errors }, () => {
      out(`${c.bold('Plugins')} ${c.dim(pluginDir())}`);
      if (!plugins.length) out(c.dim('  none installed. Copy examples/plugins/show-hn.mjs into that folder to try one.'));
      for (const p of plugins) out(`  ${c.bold(p.name)} ${c.dim(p.description ?? '')}\n    tools: ${p.tools.map((t) => `${p.name}.${t.name}`).join(', ')}`);
      for (const e of errors) out(c.red(`  failed: ${e}`));
    });
  },
  async calibrate(o, a) {
    const { calibrate } = await import('../modules/calibrate.js');
    const r = await calibrate(o.ctx, { days: Number(a.flags.days ?? 10) || 10, onDay: json(a) ? () => {} : (d) => out(c.dim(`  replaying ${d}…`)) });
    emit(a, r, () => {
      const d = r.result;
      out(c.bold(`\nCalibration · ${d.days} days replayed · ${d.samples} radar items · ${d.materialized} became news within 3 days`));
      out(c.dim('  threshold  flagged  became news  precision  recall   F1'));
      for (const row of d.rows) out(`  ${String(row.threshold).padStart(9)}  ${String(row.flagged).padStart(7)}  ${String(row.hits).padStart(11)}  ${String(row.precision ?? '-').padStart(9)}  ${String(row.recall ?? '-').padStart(6)}  ${String(row.f1 ?? '-').padStart(4)}${d.best?.threshold === row.threshold ? c.green('  <- chosen') : ''}`);
      out(c.bold('\nBy source'));
      for (const [k, v] of Object.entries(d.bySource).sort((x, y) => y[1].rate - x[1].rate)) out(`  ${k.padEnd(14)} ${String(v.samples).padStart(4)} items · ${Math.round(v.rate * 100)}% became news`);
      out(c.dim(`\nThe live radar now uses threshold ${d.best && d.best.flagged >= 10 ? d.best.threshold : '55 (not enough examples yet)'}.`));
    });
  },
  async sanctions(o, a) {
    const r = await o.sanctions(need(a, 1, 'wallet, IMO number or exact name'));
    emit(a, r, () => {
      const d = r.result;
      const col = d.verdict === 'SANCTIONED' || d.verdict === 'LISTED_ELSEWHERE' ? c.red : d.verdict === 'EXPOSED' || d.verdict === 'PEP' ? c.yellow : d.verdict === 'CLEAR' ? c.green : c.gray;
      out(`${c.bold(d.query)} · ${col(c.bold(d.verdict))} ${c.dim(`(OFAC SDN, ${d.listSize.toLocaleString('en-US')} entries${d.listDate ? `, list fetched ${d.listDate.slice(0, 10)}` : ''})`)}`);
      for (const h of d.hits) out(`  ${c.red(h.kind.padEnd(12))} ${h.entry.name} [${h.entry.program}]${h.detail ? c.dim(`  ${h.detail}`) : ''}`);
      if (d.worldwide.length) {
        out(c.bold('\n  Worldwide (OpenSanctions)'));
        for (const w of d.worldwide) out(`  ${w.score >= 0.9 ? c.red(w.score.toFixed(2)) : c.yellow(w.score.toFixed(2))} ${w.name} ${c.dim(`${w.schema}${w.countries.length ? ` · ${w.countries.join(',')}` : ''} · ${w.datasets} lists`)}  ${w.topics.join(', ')}`);
        const rel = d.worldwide[0]?.related ?? [];
        if (rel.length) {
          out(c.bold(`\n  Connected to ${d.worldwide[0]!.name}`) + c.dim(`  (${rel.filter((x) => x.sanctioned).length} of ${rel.length} sanctioned)`));
          for (const x of rel.slice(0, 15)) out(`    ${x.relation.padEnd(12)} ${x.sanctioned ? c.red(trunc(x.name, 60)) : trunc(x.name, 60)} ${c.dim(`${x.schema}${x.detail ? ` · ${x.detail}` : ''}`)}`);
        }
      }
      if (d.verdict === 'CLEAR') out(c.dim('  OFAC: exact matches only; worldwide: matches scoring 0.7+. Not legal advice.'));
      printSources(r);
    });
  },
  async markets(o, a) {
    if (!json(a)) out(c.dim('matching Polymarket with Kalshi and Manifold (an LLM confirms each pair)…'));
    const r = await o.markets(a.flags.gap ? { minGapPp: Number(a.flags.gap) } : {});
    emit(a, r, () => {
      const d = r.result;
      out(c.bold(`Market cross-check · ${d.checked} Polymarket markets · ${d.comparisons.length} matched · ${d.disagreements.length} disagreement(s)`));
      for (const x of d.comparisons.slice(0, 15)) {
        const gap = x.gapPp >= 15 ? c.red(`${x.gapPp}pp`) : `${x.gapPp}pp`;
        out(`  ${gap.padStart(6)}  PM ${String(Math.round(x.polymarket.probability * 100)).padStart(3)}% vs ${x.other.venue} ${String(Math.round(x.other.probability * 100)).padStart(3)}%  ${trunc(x.polymarket.question, 70)}${x.verified === 'unverified' ? c.dim(' (unverified match)') : ''}`);
        out(c.dim(`          ${x.other.venue}: ${trunc(x.other.question, 90)}  ${x.other.url}`));
      }
      if (!d.comparisons.length) out(c.dim('  no market on Kalshi or Manifold asks exactly the same question as the top Polymarket markets right now'));
      printSources(r);
    });
  },
  async launches(o, a) {
    const company = need(a, 1, 'company');
    const r = await o.launches(company, { ...(typeof a.flags.domain === 'string' ? { domain: a.flags.domain } : {}), ...(typeof a.flags.org === 'string' ? { org: a.flags.org } : {}), ...(a.flags.days ? { days: Number(a.flags.days) } : {}) });
    emit(a, r, () => {
      const d = r.result;
      out(c.bold(`Launch radar · ${company} · ${d.items.length} item(s) in ${d.windowDays} days`) + (d.domain ? '' : c.dim('  (add --domain to include hostnames, pages and repos)')));
      for (const i of d.items.slice(0, 30)) out(`  ${c.gray(i.date.slice(0, 10))} ${(i.kind === 'app-update' ? c.dim : c.cyan)(i.kind.padEnd(10))} ${trunc(i.title, 70)}${i.detail ? c.dim(`  ${trunc(i.detail, 60)}`) : ''}`);
      printSources(r);
    });
  },
  async rewind(o, a) {
    const r = await o.rewind(need(a, 1, 'date (YYYY-MM-DD)'));
    emit(a, r, () => {
      const d = r.result;
      out(c.bold(`Time machine · ${d.date}`));
      for (const f of d.fused.filter((x) => x.sources.some((s) => s !== 'guardian')).slice(0, 12)) out(`  [${score(f.score)}] ${c.bold(trunc(f.title, 80))} ${c.gray(f.sources.join(' + '))}`);
      if (d.headlines.length) {
        out(c.bold('\nThat day in the Guardian'));
        for (const h of d.headlines.slice(0, 8)) out(`  ${c.gray(h.time.slice(11, 16))} ${trunc(h.title, 100)}`);
      }
      out(c.dim(`\nOculon recorded ${d.oculonSignals.length} signal(s) that day.`));
      printSources(r);
    });
  },
  async fence(o, a) {
    const sub = a.pos[1];
    if (sub === 'add') {
      const name = a.pos[2];
      if (!name) throw new UsageError('usage: oculon fence add <name> <place> [--radius 100] [--kinds air,sea,quake,events] | oculon fence add <name> --box s,w,n,e');
      const kinds = typeof a.flags.kinds === 'string' ? a.flags.kinds.split(',') : undefined;
      let f;
      if (typeof a.flags.box === 'string') {
        const b = a.flags.box.split(',').map(Number) as [number, number, number, number];
        f = o.fenceAdd(name, b, kinds);
      } else f = await o.fenceAddAround(name, need(a, 3, 'place'), Number(a.flags.radius ?? 100) || 100, kinds);
      return emit(a, f, () => out(`${c.green('fence')} #${f.id} ${c.bold(f.name)} [${f.south}, ${f.west}] → [${f.north}, ${f.east}] watching ${f.kinds.join(', ')}\n${c.dim('  the first check records a baseline; later checks report what is new inside')}`));
    }
    if (sub === 'rm') {
      const ok = o.fenceRemove(Number(a.pos[2]));
      return emit(a, { removed: ok }, () => out(ok ? `removed fence #${a.pos[2]}` : `no fence #${a.pos[2]}`));
    }
    if (sub === 'check') {
      if (!json(a)) out(c.dim('checking fences (aircraft, vessels, quakes, events)…'));
      const r = await o.fenceCheck();
      return emit(a, r, () => {
        if (!r.checks.length) return out('No fences. Add one: oculon fence add hormuz "Strait of Hormuz" --radius 150');
        for (const x of r.checks) {
          const counts = c.dim(`(${x.counts.milAircraft} mil aircraft, ${x.counts.milVessels} mil vessels, ${x.counts.quakes} quakes, ${x.counts.events} events now)`);
          out(`  #${x.fence.id} ${c.bold(x.fence.name)} ${x.baseline ? c.dim('baseline recorded') : x.changes.length ? c.yellow(`${x.changes.length} new`) : c.dim('nothing new')} ${counts}`);
          for (const ch of x.changes) out(`      - ${ch}`);
        }
      });
    }
    const list = o.fenceList();
    emit(a, list, () => {
      if (!list.length) return out('No fences. Add one: oculon fence add hormuz "Strait of Hormuz" --radius 150');
      for (const f of list) out(`  #${f.id} ${c.bold(f.name.padEnd(16))} [${f.south}, ${f.west}] → [${f.north}, ${f.east}]  ${f.kinds.join(',')}  ${c.dim(f.lastRun ? `checked ${f.lastRun.slice(0, 16)}Z` : 'not checked yet')}`);
    });
  },
  async scoops(o, a) {
    if (a.pos[1] === 'check') {
      if (!json(a)) out(c.dim('checking strong signals against Guardian, NYT and GNews…'));
      const r = await o.scoopsCheck(Number(a.flags.max ?? 8) || 8);
      if (json(a)) return out(JSON.stringify(r, null, 2));
      for (const s of r) out(`  ${s.leadHours === null ? c.dim('no coverage yet') : s.leadHours > 0 ? c.green(`Oculon +${s.leadHours}h`) : c.yellow(`media first ${s.leadHours}h`)}  ${trunc(s.subject, 70)}${s.mediaSource ? c.dim(`  (${s.mediaSource})`) : ''}`);
      if (!r.length) out(c.dim('  nothing due: signals are checked once they are 6-72 hours old'));
    }
    const b = o.scoops();
    emit(a, b, () => {
      out(c.bold(`\nFirst to Know · ${b.checked} signals checked · ${b.covered} covered by media`));
      if (b.covered) out(`  Oculon first ${c.green(String(b.oculonFirst))} · media first ${c.yellow(String(b.mediaFirst))} · median lead ${b.medianLeadHours !== null ? `${b.medianLeadHours > 0 ? '+' : ''}${b.medianLeadHours}h` : 'n/a'}`);
      for (const s of b.best.slice(0, 8)) out(`  ${c.green(`+${s.leadHours}h`.padStart(8))}  ${trunc(s.subject, 70)}  ${c.dim(`${s.mediaSource ?? ''} ${s.mediaUrl ?? ''}`)}`);
      if (b.pending.length) out(c.dim(`  ${b.pending.length} signal(s) still without media coverage`));
    });
  },
  async case(o, a) {
    const sub = a.pos[1];
    if (sub === 'new' || sub === 'rerun') {
      const input = sub === 'new' ? { question: need(a, 2, 'question') } : { id: Number(a.pos[2]) };
      if (!json(a)) out(c.dim(sub === 'new' ? `opening case: ${input.question}` : `re-investigating case #${a.pos[2]}`));
      const r = await o.caseInvestigate(input, { onStep: json(a) ? () => {} : (s) => out(c.dim(`  → ${trunc(s, 120)}`)) });
      return emit(a, r, () => {
        out(`\n${r.case.markdown ?? ''}`);
        if (r.added.length) out(c.yellow(`\n${r.added.length} new finding(s) since the previous run`));
      });
    }
    if (sub === 'watch') {
      const ok = await o.caseWatch(Number(a.pos[2]), a.pos[3] !== 'off');
      return emit(a, { ok }, () => out(ok ? `case #${a.pos[2]} watch ${a.pos[3] === 'off' ? 'off' : 'on (re-investigated daily, new findings become signals)'}` : `no case #${a.pos[2]}`));
    }
    if (sub === 'show') {
      const k = await o.caseGet(Number(a.pos[2]));
      return emit(a, k, () => out(k?.markdown ?? `no case #${a.pos[2]}`));
    }
    const list = await o.caseList();
    emit(a, list, () => {
      if (!list.length) return out('No cases yet. Open one: oculon case new "who is behind token 0x..?"');
      for (const k of list) out(`  #${String(k.id).padEnd(3)} ${trunc(k.question, 70).padEnd(70)} ${c.dim(`${k.report?.confidence ?? '-'} · ${k.report?.findings.length ?? 0} findings · run ${k.runs}`)}${k.watch ? c.green(' watching') : ''}`);
    });
  },
  async watch(o, a) {
    const sub = a.pos[1];
    if (sub === 'add') {
      const kind = a.pos[2];
      const target = a.pos.slice(3).join(' ').trim();
      if (!kind || !target) throw new UsageError('usage: oculon watch add <kind> <target> [--label name]   (or describe it: oculon monitor "...")');
      const item = o.watchAdd(kind, target, typeof a.flags.label === 'string' ? a.flags.label : undefined);
      return emit(a, item, () => out(`${c.green('watching')} #${item.id} ${item.kind} ${c.bold(item.target)}${item.label ? c.dim(` (${item.label})`) : ''}\n${c.dim('  the first `oculon watch run` records a baseline; later runs report changes')}`));
    }
    if (sub === 'rm' || sub === 'remove') {
      const id = Number(a.pos[2]);
      const ok = Number.isInteger(id) && o.watchRemove(id);
      return emit(a, { removed: ok }, () => out(ok ? `removed #${id}` : `no watch item #${a.pos[2]}`));
    }
    if (sub === 'run') {
      const r = await o.watchRun();
      return emit(a, r, () => {
        if (!r.runs.length) return out('Watchlist is empty. Add something: oculon watch add company Nvidia');
        for (const x of r.runs) {
          const head = `  #${x.item.id} ${x.item.kind.padEnd(8)} ${c.bold(x.item.label ?? x.item.target)}`;
          if (x.error) out(`${head}  ${c.red(`error: ${trunc(x.error, 100)}`)}`);
          else if (x.baseline) out(`${head}  ${c.dim('baseline recorded')}`);
          else if (!x.changes.length) out(`${head}  ${c.dim('no change')}`);
          else {
            out(`${head}  ${c.yellow(`${x.changes.length} change(s)`)}`);
            for (const ch of x.changes) out(`        - ${trunc(ch, 140)}`);
          }
        }
      });
    }
    const list = o.watchList();
    emit(a, list, () => {
      if (!list.length) return out('Watchlist is empty. Add something: oculon watch add company Nvidia');
      for (const w of list) out(`  #${String(w.id).padEnd(3)} ${w.kind.padEnd(8)} ${c.bold(w.target)}${w.label ? c.dim(` (${w.label})`) : ''}  ${c.dim(w.lastRun ? `last run ${w.lastRun.slice(0, 16)}Z` : 'not run yet')}`);
    });
  },
  async gc(o, a) {
    const days = Number(a.flags.days ?? 14) || 14;
    const r = o.ctx.store.pruneCache(days, true);
    emit(a, r, () => out(`Removed ${r.removed} cached API response(s) older than ${days} days and compacted the database.`));
  },
  async tour(o, a) {
    // A quick look at what this install already knows, using stored data only (no API calls), then where to go next.
    const db = o.ctx.store.db;
    const count = (sql: string) => Number((db.prepare(sql).get() as { n: number }).n);
    const stats = {
      signals: count('SELECT count(*) n FROM signals'),
      entities: count('SELECT count(*) n FROM entities'),
      links: count('SELECT count(*) n FROM edges'),
      watch: o.watchList().length,
      cases: count('SELECT count(*) n FROM cases'),
      forecasts: count('SELECT count(*) n FROM predictions'),
    };
    const top = o.signals(200).sort((x, y) => y.score - x.score).slice(0, 3);
    const pair = db
      .prepare("SELECT a.name AS a, b.name AS b FROM edges e JOIN entities a ON a.id = e.src JOIN entities b ON b.id = e.dst WHERE a.kind IN ('company','org') AND b.kind IN ('topic','repo','domain') LIMIT 1")
      .get() as { a: string; b: string } | undefined;
    emit(a, { stats, top }, () => {
      out(`${c.bold('Oculon tour')} ${c.dim(`v${VERSION} · data in ${oculonHome()}`)}`);
      out(`\n  ${stats.signals} signals · ${stats.entities} entities with ${stats.links} links · ${stats.watch} watched · ${stats.cases} cases · ${stats.forecasts} forecasts`);
      if (!stats.signals) {
        out(`\n  ${c.bold('Start here')}`);
        out(`    oculon doctor          check keys and sources`);
        out(`    oculon radar           first scan of what the world is suddenly watching`);
        out(`    oculon dossier Nvidia  a full dossier on one company`);
        return;
      }
      out(`\n  ${c.bold('Strongest stored signals')}`);
      printSignals(top, 3);
      out(`\n  ${c.bold('Try next')}`);
      const tips = [
        ['oculon ask "What changed for Nvidia this week?"', 'the agent answers using every tool'],
        ['oculon calendar 7', "the week's earnings, macro releases and closing markets"],
        [pair ? `oculon connect "${pair.a}" to "${pair.b}"` : 'oculon connect <A> to <B>', 'how two things link in your graph'],
        ['oculon case new "<question>"', 'a deep investigation with sourced findings'],
        ['oculon watch add company <name>', 'get told when something changes'],
        ['oculon serve --watch 15 --live', 'dashboard, schedule and live streams together'],
      ];
      for (const [cmd, why] of tips) out(`    ${c.cyan(cmd!.padEnd(52))} ${c.dim(why!)}`);
    });
  },
  async sentinel(o, a) {
    const r = await o.sentinel(need(a, 1, 'place'), {
      ...(typeof a.flags.date === 'string' ? { date: a.flags.date } : {}),
      ...(typeof a.flags.compare === 'string' ? { compareTo: a.flags.compare } : {}),
      ...(a.flags.days ? { days: Number(a.flags.days) } : {}),
      kind: a.flags.radar ? 'radar' : 'optical',
    });
    const shots = r.result.shots.map((s, i) => {
      let file = s.file;
      if (file && typeof a.flags.out === 'string') {
        const dest = resolve(i === 0 ? a.flags.out : a.flags.out.replace(/(\.png)?$/i, '-before.png'));
        mkdirSync(dirname(dest), { recursive: true });
        copyFileSync(file, dest);
        file = dest;
      }
      return { ...s, file };
    });
    emit(a, { ...r, result: { shots } }, () => {
      out(c.bold(`${shots[0]!.place.name}`) + c.dim(`  Sentinel-${shots[0]!.kind === 'radar' ? '1 radar' : '2 optical, 10 m'}`));
      for (const s of shots) out(s.file ? `  ${s.from} to ${s.to}  saved ${s.file}` : c.yellow(`  ${s.from} to ${s.to}  no image (${r.provenance.at(-1)?.note ?? 'no data'})`));
      printSources(r);
    });
  },
  async fires(o, a) {
    const r = await o.fires(need(a, 1, 'place'), Number(a.flags.days ?? 2) || 2);
    emit(a, r, () => {
      const f = r.result;
      if (!f.place) return out(c.yellow('place not found'));
      out(c.bold(`Fires near ${f.place.name.split(',')[0]} · last ${f.days} day(s) · ${f.hotspots.length} hotspots`) + c.dim(`  ${f.high} high confidence, ${f.totalFrp} MW total`));
      for (const cl of f.clusters.slice(0, 15)) out(`  ${String(cl.count).padStart(4)} hotspots  ${String(cl.frp).padStart(6)} MW  ${cl.lat.toFixed(3)}, ${cl.lon.toFixed(3)}  ${c.gray(cl.last.slice(0, 16).replace('T', ' '))}`);
      if (!f.hotspots.length) out(c.dim('  none detected'));
      printSignals(r.signals);
      printSources(r);
    });
  },
  async darkships(o, a) {
    const r = await o.darkShips(need(a, 1, 'place'), Number(a.flags.days ?? 30) || 30);
    emit(a, r, () => {
      const d = r.result;
      if (!d.place) return out(c.yellow('place not found'));
      out(c.bold(`AIS switched off near ${d.place.name.split(',')[0]} · last ${d.days} days · ${d.total} vessel gaps`));
      for (const g of d.gaps.slice(0, 25)) out(`  ${c.gray(g.on.slice(0, 10))} ${c.bold(trunc(g.vessel, 28).padEnd(28))} ${(g.flag ?? '?').padEnd(4)} ${c.dim((g.type ?? '').padEnd(10))} dark ${String(g.hours).padStart(5)} h, moved ${g.km} km`);
      if (!d.total) out(c.dim('  none in Global Fishing Watch data (its gap model covers fishing and carrier vessels best)'));
      const vn = (v: { name: string; flag: string | null; sanctioned?: string | null }) => `${v.name}${v.flag ? ` (${v.flag})` : ''}${v.sanctioned ? c.red(' OFAC') : ''}`;
      if (d.encounters?.length) {
        out(`\n  ${c.bold(`Ship-to-ship encounters · ${d.encounters.length}`)}${c.dim('  (possible transfers at sea)')}`);
        for (const e of d.encounters.slice(0, 12)) out(`    ${c.gray(e.start.slice(0, 10))} ${vn(e.a)} × ${vn(e.b)} ${c.dim(`${e.hours} h${e.kind ? `, ${e.kind}` : ''}`)}${e.gapLinked ? c.yellow(' one went dark') : ''}${e.potentialRisk ? c.yellow(' unauthorized') : ''}`);
      }
      if (d.loitering?.length) out(`\n  ${c.bold(`Loitering · ${d.loitering.length}`)} ${c.dim(`${d.loitering.filter((x) => x.linked).length} by vessels that also went dark or met another ship`)}`);
      if (d.portVisits?.length) {
        out(`\n  ${c.bold('Where those vessels went')}`);
        for (const p of d.portVisits.slice(0, 8)) out(`    ${c.gray(p.start.slice(0, 10))} ${vn(p.vessel)} → ${p.port ?? '?'}${p.portFlag ? ` (${p.portFlag})` : ''}`);
      }
      printSignals(r.signals);
      printSources(r);
    });
  },
  async vessel(o, a) {
    const r = await o.vessel(need(a, 1, 'vessel name, MMSI or IMO'));
    emit(a, r, () => {
      if (!r.result.length) return out('No vessel found.');
      for (const v of r.result) {
        out(`${c.bold(v.name ?? '?')}  IMO ${v.imo ?? '?'} · MMSI ${v.mmsi ?? '?'} · flag ${v.flag ?? '?'} · ${v.types.join('/') || '?'}${v.sanctions ? `  OFAC ${v.sanctions === 'CLEAR' ? c.green(v.sanctions) : c.red(v.sanctions)}` : ''}`);
        out(c.dim(`  AIS ${(v.firstSeen ?? '?').slice(0, 10)} to ${(v.lastSeen ?? '?').slice(0, 10)}${v.callsign ? ` · callsign ${v.callsign}` : ''}`));
        for (const ow of v.owners.slice(0, 4)) out(`  owner ${ow.name}${ow.flag ? ` (${ow.flag})` : ''}${ow.from ? c.dim(` ${ow.from.slice(0, 10)} to ${(ow.to ?? 'now').slice(0, 10)}`) : ''}`);
        if (v.earlierNames.length) out(`  earlier names: ${v.earlierNames.join(', ')}`);
        if (v.history) {
          const h = v.history;
          out(`  last ${h.days} days: ${h.gaps} AIS gaps, ${h.encounters} encounters, ${h.loitering} loitering, ${h.portVisits} port visits`);
          if (h.ports.length) out(`  ports ${h.ports.slice(0, 6).map((p) => `${p.port}${p.flag ? ` (${p.flag})` : ''} ×${p.visits}`).join(', ')}`);
        }
      }
      printSources(r);
    });
  },
  async cloud(o, a) {
    const r = await o.cloud();
    emit(a, r, () => {
      const st = r.result;
      out(c.bold(`Service status · ${st.checked} platforms · ${st.incidents.length} open incidents`));
      for (const i of st.incidents.slice(0, 25)) {
        const col = i.impact === 'critical' || i.impact === 'major' ? c.red : i.impact === 'minor' ? c.yellow : c.gray;
        out(`  ${col(i.impact.padEnd(8))} ${c.bold(i.service.padEnd(13))} ${trunc(i.title, 80)} ${c.dim(i.updated.slice(0, 16).replace('T', ' '))}`);
      }
      if (st.degraded.length) out(`\n  ${c.dim('degraded:')} ${st.degraded.map((d) => `${d.service} (${d.description || d.indicator})`).join(', ')}`);
      if (!st.incidents.length && !st.degraded.length) out(c.green('  all checked platforms report no open incidents'));
      printSignals(r.signals);
      printSources(r);
    });
  },
  async bgp(o, a) {
    const r = await o.bgp(a.pos[1] ?? 'world', Number(a.flags.days ?? 2) || 2);
    emit(a, r, () => {
      const { country, asn, ip, incidents } = r.result;
      const printIncidents = () => {
        if (!incidents) return;
        if (incidents.attacks) {
          const fmt = (l: { name: string; share: number }[]) => l.slice(0, 6).map((x) => `${x.name} ${Math.round(x.share * 100)}%`).join(', ');
          out(`\n  ${c.bold('DDoS targets, last 24h')} ${c.dim('(share of attack traffic Cloudflare saw)')}`);
          out(`    application layer: ${fmt(incidents.attacks.layer7)}`);
          out(`    network layer:     ${fmt(incidents.attacks.layer3)}`);
        }
        const hj = incidents.hijacks.filter((h) => h.confidence >= 9 && !h.sameOrg).slice(0, 10);
        out(`\n  ${c.bold(`BGP hijacks · ${incidents.hijacks.length} detected`)}${c.dim(', showing confidence 9+ between different organisations')}`);
        for (const h of hj) out(`    ${h.ongoing ? c.red('ongoing') : c.dim('ended  ')} ${c.gray(h.start.slice(0, 16).replace('T', ' '))} ${trunc(`${h.hijacker} took ${h.prefixes.slice(0, 2).join(', ')}${h.prefixes.length > 2 ? ` +${h.prefixes.length - 2}` : ''} from ${h.victims.slice(0, 2).join(', ') || '?'}`, 110)} ${c.dim(`${h.peers} peers`)}`);
        if (!hj.length) out(c.dim('    none with high confidence'));
        out(`\n  ${c.bold(`Route leaks · ${incidents.leaks.length}`)}`);
        for (const l of incidents.leaks.slice(0, 8)) out(`    ${l.finished ? c.dim('ended  ') : c.red('ongoing')} ${c.gray(l.start.slice(0, 16).replace('T', ' '))} ${trunc(`${l.leaker}: ${l.prefixes} prefixes from ${l.origins} networks via ${l.path.join(' > ')}`, 110)}`);
      };
      if (ip) {
        out(`${c.bold(ip.ip)} ${c.dim(ip.prefix ?? '')}  ${ip.announced ? c.green('announced') : c.red('not announced')}`);
        out(`  network ${ip.origins.map((x) => `${x.name} (${x.asn})`).join(', ') || '?'}`);
        out(`  RPKI ${ip.rpki === 'valid' ? c.green('valid') : ip.rpki === 'invalid' ? c.red('INVALID (possible hijack or misconfiguration)') : c.dim(ip.rpki ?? 'unknown')}`);
        out(`  location ${[ip.city, ip.country].filter(Boolean).join(', ') || '?'} · registry ${ip.registry ?? '?'}`);
        if (ip.abuse.length) out(`  abuse contact ${ip.abuse.join(', ')}`);
      } else if (asn) {
        out(`${c.bold(asn.asn)} ${asn.name ?? ''}`);
        if (asn.visibilityV4 === null) out(c.dim('  RIPEstat routing status timed out (very large networks can take minutes)'));
        else {
          out(`  visible to ${Math.round((asn.visibilityV4 ?? 0) * 100)}% of RIPE peers (IPv4), ${Math.round((asn.visibilityV6 ?? 0) * 100)}% (IPv6)`);
          out(`  announces ${asn.prefixesV4} IPv4 and ${asn.prefixesV6} IPv6 prefixes · ${asn.neighbours} neighbours`);
        }
        printIncidents();
      } else if (!country && incidents) {
        out(c.bold('Global routing incidents'));
        printIncidents();
      } else if (country?.latest && country.baseline) {
        const ch = country.v4Change ?? 0;
        out(`${c.bold(country.country)} routing · ${country.latest.v4} IPv4 prefixes visible now vs ${country.baseline.v4} usual ${ch <= -0.05 ? c.red(`(${(ch * 100).toFixed(1)}%)`) : c.dim(`(${(ch * 100).toFixed(1)}%)`)}`);
        const max = Math.max(...country.series.map((s) => s.v4));
        const min = Math.min(...country.series.map((s) => s.v4));
        const bars = '▁▂▃▄▅▆▇█';
        out(`  ${country.series.map((s) => bars[max === min ? 7 : Math.round(((s.v4 - min) / (max - min)) * 7)]).join('')}  ${c.dim(`${min}–${max} over ${country.series.length} h`)}`);
        printIncidents();
      } else out('No routing data.');
      printSignals(r.signals);
      printSources(r);
    });
  },
  async vulns(o, a) {
    const r = await o.vulns({ days: Number(a.pos[1] ?? a.flags.days ?? 7) || 7, ...(typeof a.flags.vendor === 'string' ? { vendor: a.flags.vendor } : {}) });
    emit(a, r, () => {
      const v = r.result;
      out(c.bold(`Vulnerabilities ${v.window.from.slice(0, 10)} to ${v.window.to.slice(0, 10)}${v.vendor ? ` · ${v.vendor}` : ''}`) + c.dim(v.catalog ? `  CISA KEV ${v.catalog.count} entries, version ${v.catalog.version}` : ''));
      out(`\n  ${c.bold(`Newly exploited in the wild (CISA KEV) · ${v.kev.length}`)}`);
      for (const k of v.kev.slice(0, 20)) out(`    ${c.gray(k.dateAdded)} ${c.red(k.cveID.padEnd(16))} ${trunc(k.vulnerabilityName, 80)}${k.knownRansomwareCampaignUse === 'Known' ? c.red(' ransomware') : ''}${k.epss != null ? c.dim(` EPSS ${k.epss.toFixed(2)}`) : ''}${k.daysToDue != null ? c.dim(k.daysToDue < 0 ? ` federal deadline passed ${-k.daysToDue}d ago` : ` federal deadline in ${k.daysToDue}d`) : ''}`);
      out(`\n  ${c.bold(`New critical CVEs (NVD) · ${v.criticalCves.length}`)}`);
      for (const x of v.criticalCves.slice(0, 10)) out(`    ${c.gray(x.published.slice(0, 10))} ${x.id.padEnd(16)} ${x.cvss ?? '?'} ${c.dim(trunc(x.description, 90))}`);
      const adv = (v as { advisories?: { id: string; summary: string; published: string; packages: { ecosystem: string; name: string }[] }[] }).advisories ?? [];
      if (adv.length) {
        out(`\n  ${c.bold(`Critical package advisories (GitHub) · ${adv.length}`)}`);
        for (const x of adv.slice(0, 10)) out(`    ${c.gray(x.published.slice(0, 10))} ${x.id} ${trunc(`${x.packages.map((p) => `${p.ecosystem}/${p.name}`).slice(0, 2).join(', ')}: ${x.summary}`, 90)}`);
      }
      printSignals(r.signals);
      printSources(r);
    });
  },
  async cve(o, a) {
    const r = await o.cve(need(a, 1, 'CVE id, e.g. CVE-2021-44228'));
    emit(a, r, () => {
      const d = r.result;
      out(`${c.bold(d.id)} ${d.cvss ? `${d.cvss.score >= 9 ? c.red(`${d.cvss.score} ${d.cvss.severity}`) : `${d.cvss.score} ${d.cvss.severity}`} ${c.dim(`CVSS ${d.cvss.version}`)}` : c.dim('no CVSS yet')}${d.kev ? c.red('  EXPLOITED IN THE WILD (CISA KEV)') : ''}`);
      out(`  ${trunc(d.description, 300)}`);
      if (d.epss) out(`  EPSS ${(d.epss.score * 100).toFixed(1)}% chance of exploitation in 30 days (percentile ${Math.round(d.epss.percentile * 100)})`);
      if (d.kev) out(`  KEV since ${d.kev.dateAdded}, federal due date ${d.kev.dueDate}${d.kev.knownRansomwareCampaignUse === 'Known' ? ', used by ransomware' : ''}`);
      if (d.products.length) out(`  products ${trunc(d.products.join(', '), 120)}`);
      for (const p of d.packages.slice(0, 8)) out(`  package ${p.ecosystem}/${p.name}${p.fixed.length ? ` fixed in ${p.fixed.join(', ')}` : c.yellow(' no fix listed')}`);
      if (d.cwes.length) out(c.dim(`  ${d.cwes.join(', ')}`));
      printSignals(r.signals);
      printSources(r);
    });
  },
  async pkg(o, a) {
    const [eco, name, version] = [a.pos[1], a.pos[2], a.pos[3]];
    if (!eco || !name) throw new UsageError('usage: oculon pkg <ecosystem> <name> [version], e.g. oculon pkg npm lodash 4.17.15');
    const r = await o.packageVulns(eco, name, version);
    emit(a, r, () => {
      const p = r.result;
      out(c.bold(`${p.ecosystem}/${p.name}${p.version ? `@${p.version}` : ''} · ${p.vulns.length} known vulnerabilities`) + c.dim('  (OSV.dev)'));
      for (const v of p.vulns.slice(0, 25)) {
        const x = v as unknown as { id: string; aliases?: string[]; summary?: string; severity?: string; fixed?: string[]; exploited?: boolean };
        out(`  ${x.exploited ? c.red('exploited') : '         '} ${x.id.padEnd(20)} ${trunc(x.summary ?? '', 70)}${x.fixed?.length ? c.dim(` fix ${x.fixed.join(', ')}`) : ''}`);
      }
      if (!p.vulns.length) out(c.green('  none known'));
      printSignals(r.signals);
      printSources(r);
    });
  },
  async regs(o, a) {
    const r = await o.regs({ days: Number(a.flags.days ?? 7) || 7, ...(a.pos[1] ? { query: a.pos.slice(1).join(' ') } : {}), ...(typeof a.flags.agency === 'string' ? { agency: a.flags.agency } : {}) });
    emit(a, r, () => {
      const g = r.result;
      out(c.bold(`US Federal Register ${g.window.from.slice(0, 10)} to ${g.window.to.slice(0, 10)}${g.query ? ` · "${g.query}"` : ''}${g.agency ? ` · ${g.agency}` : ''}`));
      if (g.executiveOrders.length) {
        out(`\n  ${c.bold('Executive orders')}`);
        for (const d of g.executiveOrders.slice(0, 8)) out(`    ${c.gray(d.publicationDate)} ${c.red(`EO ${d.executiveOrder ?? ''}`)} ${trunc(d.title, 100)}`);
      }
      if (g.publicInspection.length) {
        out(`\n  ${c.bold(`Public inspection (publishes next) · ${g.publicInspection.length}`)}`);
        for (const d of g.publicInspection.slice(0, 8)) out(`    ${c.gray(d.publicationDate)} ${c.dim(d.type.padEnd(14))} ${trunc(`${d.agencies[0] ?? ''}: ${d.title}`, 100)}`);
      }
      out(`\n  ${c.bold(`Documents · ${g.documents.length}`)}`);
      for (const d of g.documents.slice(0, 20)) out(`    ${c.gray(d.publicationDate)} ${(d.significant ? c.yellow : c.dim)(d.type.padEnd(14))} ${trunc(`${d.agencies[0] ?? ''}: ${d.title}`, 100)}${d.effectiveOn ? c.dim(` effective ${d.effectiveOn}`) : ''}${d.commentsCloseOn ? c.dim(` comments close ${d.commentsCloseOn}`) : ''}`);
      printSignals(r.signals);
      printSources(r);
    });
  },
  async defi(o, a) {
    const r = await o.defi();
    emit(a, r, () => {
      const d = r.result;
      const usd = (n: number | null | undefined) => (n == null ? '?' : n >= 1e9 ? `$${(n / 1e9).toFixed(2)}B` : n >= 1e6 ? `$${(n / 1e6).toFixed(1)}M` : `$${Math.round(n / 1e3)}k`);
      const pct = (n: number | null | undefined) => (n == null ? '' : `${n >= 0 ? '+' : ''}${n.toFixed(1)}%`);
      const t = d.totals;
      out(c.bold(`DeFi risk radar`) + c.dim(`  TVL ${usd(t.defiTvl)} ${pct(t.defiTvlChange1d)} 1d · stablecoins ${usd(t.stablecoinSupply)} · DEX volume ${usd(t.dexVolume24h)} · fees ${usd(t.fees24h)}`));
      if (d.fearGreed) out(`  Fear & Greed ${d.fearGreed.value} ${d.fearGreed.label}${c.dim(`, 7d avg ${d.fearGreed.avg7d ?? '?'}, 30d avg ${d.fearGreed.avg30d ?? '?'}, ${d.fearGreed.trend}`)}`);
      out(`\n  ${c.bold(`TVL crashes · ${d.tvlDrops.length}`)}`);
      for (const p of d.tvlDrops.slice(0, 12)) out(`    ${c.red(pct(p.change1d).padStart(7))} ${c.bold(trunc(p.name, 28).padEnd(28))} ${usd(p.prevTvl)} → ${usd(p.tvl)} ${c.dim(`${p.category}${p.vsMarketPct != null ? `, ${pct(p.vsMarketPct)} vs market` : ''}${p.flags.length ? `, ${p.flags.join(', ')}` : ''}`)}`);
      out(`\n  ${c.bold(`Stablecoin depegs · ${d.depegs.length}`)}${d.supplyShocks.length ? c.dim(`  · ${d.supplyShocks.length} supply shocks`) : ''}`);
      for (const s of [...d.depegs, ...d.supplyShocks].slice(0, 10)) out(`    ${s.symbol.padEnd(10)} $${s.price.toFixed(4)} ${Math.abs(s.offPct) >= 2 ? c.red(`${Math.abs(s.offPct).toFixed(1)}% off peg`) : c.dim(`${Math.abs(s.offPct).toFixed(1)}% off peg`)} ${c.dim(`supply ${usd(s.circulating)}${s.supplyChange1dPct != null ? ` (${pct(s.supplyChange1dPct)} 1d)` : ''}, ${s.mechanism}`)}`);
      if (d.hacks.length) {
        out(`\n  ${c.bold(`Hacks, last 7 days · ${d.hacks.length}`)}`);
        for (const h of d.hacks.slice(0, 8)) out(`    ${c.gray(h.date.slice(0, 10))} ${c.red(usd(h.amount).padStart(8))} ${trunc(`${h.name}: ${h.technique || h.classification}`, 80)} ${c.dim(h.chains.join(', '))}`);
      }
      if (d.chains.moves.length) out(`\n  ${c.dim('chain moves:')} ${d.chains.moves.slice(0, 6).map((m) => `${m.name} ${pct(m.changePct)}`).join(', ')}`);
      printSignals(r.signals);
      printSources(r);
    });
  },
  async protocol(o, a) {
    const r = await o.protocol(need(a, 1, 'protocol name, e.g. aave'));
    emit(a, r, () => {
      const p = r.result;
      if (!p) return out(c.yellow('protocol not found on DefiLlama'));
      const usd = (n: number | null | undefined) => (n == null ? '?' : n >= 1e9 ? `$${(n / 1e9).toFixed(2)}B` : n >= 1e6 ? `$${(n / 1e6).toFixed(1)}M` : `$${Math.round(n / 1e3)}k`);
      const pct = (n: number | null | undefined) => (n == null ? '?' : `${n >= 0 ? '+' : ''}${n.toFixed(1)}%`);
      out(`${c.bold(p.name)} ${c.dim(`${p.category} · ${p.url}`)}`);
      out(`  TVL ${usd(p.tvl)} · 1d ${pct(p.change.d1)} · 7d ${pct(p.change.d7)} · 30d ${pct(p.change.d30)} · 1y ${pct(p.change.d365)}${p.ath && p.drawdownFromAthPct != null ? c.dim(` · ${Math.abs(p.drawdownFromAthPct).toFixed(1)}% below its high of ${usd(p.ath.tvl)} on ${p.ath.date}`) : ''}`);
      if (p.chains.length) out(`  chains ${p.chains.slice(0, 6).map((x) => `${x.chain} ${usd(x.tvl)}`).join(', ')}`);
      out(`  audits ${p.audits ?? '?'}${p.auditLinks.length ? c.dim(` ${p.auditLinks.slice(0, 2).join(' ')}`) : ''}${p.oracles.length ? ` · oracles ${p.oracles.join(', ')}` : ''}`);
      const extra = p as unknown as { hacks?: { date: string; amount: number; technique?: string }[]; warnings?: string[] };
      for (const h of extra.hacks ?? []) out(c.red(`  hacked ${h.date.slice(0, 10)}: ${usd(h.amount)}${h.technique ? `, ${h.technique}` : ''}`));
      for (const w of extra.warnings ?? []) out(c.yellow(`  warning: ${trunc(w, 120)}`));
      printSignals(r.signals);
      printSources(r);
    });
  },
  async squawk(o, a) {
    const r = await o.squawks();
    emit(a, r, () => {
      const s = r.result;
      out(c.bold(`Emergency squawks · ${s.total} aircraft`) + c.dim(`  7500 ${s.byCode['7500']} · 7700 ${s.byCode['7700']} · 7600 ${s.byCode['7600']} · ${s.ignored} ignored as ground or stale`));
      for (const x of s.aircraft) out(`  ${x.code === '7500' ? c.red(x.code) : x.code === '7700' ? c.yellow(x.code) : x.code} ${c.bold((x.callsign ?? x.hex).padEnd(9))} ${(x.registration ?? '').padEnd(9)} ${(x.type ?? '').padEnd(5)} ${x.altFt ?? '?'} ft ${x.speedKt ?? '?'} kt  ${x.nearestAirport ? `${x.nearestAirport.km} km from ${x.nearestAirport.name}` : `${x.lat?.toFixed(2)}, ${x.lon?.toFixed(2)}`}${x.emergency ? c.dim(` (${x.emergency})`) : ''}`);
      if (!s.total) out(c.green('  no aircraft squawking an emergency code right now'));
      printSignals(r.signals);
      printSources(r);
    });
  },
  async filings(o, a) {
    const q = need(a, 1, 'phrase, e.g. "cybersecurity incident"');
    const forms = typeof a.flags.forms === 'string' ? a.flags.forms.split(',') : undefined;
    const r = await o.filings(q, { days: Number(a.flags.days ?? 30) || 30, ...(forms ? { forms } : {}) });
    emit(a, r, () => {
      const f = r.result;
      out(c.bold(`SEC full-text search · ${f.query} · ${f.from} to ${f.to} · ${f.total}${f.totalIsLowerBound ? '+' : ''} filings`) + c.dim(f.forms.length ? `  forms ${f.forms.join(',')}` : ''));
      for (const h of f.hits.slice(0, 25)) out(`  ${c.gray(h.filed)} ${h.form.padEnd(6)} ${c.bold(trunc(`${h.company}${h.ticker ? ` (${h.ticker})` : ''}`, 40).padEnd(40))} ${c.dim(trunc(h.itemTitles.join('; '), 60))}`);
      if (f.topCompanies.length) out(`\n  ${c.dim('most filings:')} ${f.topCompanies.slice(0, 6).map((x) => `${x.name} (${x.docs})`).join(', ')}`);
      printSources(r);
    });
  },
  async edgar(o, a) {
    const r = await o.secEvents(need(a, 1, 'ticker or CIK'), Number(a.flags.days ?? 90) || 90);
    emit(a, r, () => {
      const e = r.result;
      out(c.bold(`8-K events · ${e.company?.name ?? a.pos[1]} · last ${e.days} days · ${e.events.length}`));
      for (const x of e.events) out(`  ${c.gray(x.date)} ${x.impact >= 70 ? c.red(String(x.impact).padStart(3)) : c.dim(String(x.impact).padStart(3))} ${trunc(x.summary, 110)}${x.officerDeparture ? c.red(` ${x.officerDeparture} leaving`) : ''}`);
      if (!e.events.length) out(c.dim('  no 8-K filings in the window'));
      printSignals(r.signals);
      printSources(r);
    });
  },
  async blackout(o, a) {
    const r = await o.blackout(Number(a.pos[1] ?? a.flags.days ?? 2) || 2);
    emit(a, r, () => {
      const b = r.result;
      out(c.bold(`Internet outages · last ${b.days} days · ${b.outages.length} events`));
      for (const x of b.outages.slice(0, 20)) {
        const where = `${x.country ?? '?'}${x.network ? ` · ${x.network}` : ''}`;
        out(`  ${x.verified ? c.red('●') : c.yellow('○')} ${c.gray(x.start.slice(0, 16).replace('T', ' '))} ${c.bold(trunc(where, 60))}${x.cause ? c.dim(` ${x.cause}`) : ''}${x.end ? '' : c.red(' ongoing')}`);
        out(c.dim(`      ${trunc(x.description, 110)}`));
      }
      for (const rt of b.routing) out(`  ${c.dim('routing')} ${rt.country}: ${rt.v4Now} IPv4 prefixes visible vs ${rt.v4Baseline} usual ${rt.change <= -0.05 ? c.red(`(${(rt.change * 100).toFixed(1)}%)`) : c.dim(`(${(rt.change * 100).toFixed(1)}%)`)}`);
      if (b.ioda.length) out(`\n  ${c.dim('IODA top countries by outage score:')} ${b.ioda.slice(0, 8).map((x) => `${x.name} (${x.events})`).join(', ')}`);
      out(c.dim('  ● confirmed or verified by Cloudflare  ○ automatic anomaly'));
      printSignals(r.signals);
      printSources(r);
    });
  },
  async hazards(o, a) {
    const r = await o.hazards(Number(a.pos[1] ?? a.flags.days ?? 7) || 7);
    emit(a, r, () => {
      out(c.bold(`GDACS disaster alerts · ${r.result.length}`));
      for (const x of (r.result as { bulletins?: { source: string; title: string; category: string; area: string; issued: string }[] }).bulletins?.filter((x) => x.source !== 'NWS') ?? []) out(`  ${/warning|advisory|watch|threat/i.test(x.category) ? c.red('tsunami') : c.dim('tsunami')} ${c.gray(x.issued.slice(0, 16).replace('T', ' '))} ${x.category}: ${trunc(x.title, 70)}`);
      const nws = (r.result as { bulletins?: { source: string; title: string }[] }).bulletins?.filter((x) => x.source === 'NWS') ?? [];
      if (nws.length) {
        const counts = new Map<string, number>();
        for (const x of nws) counts.set(x.title, (counts.get(x.title) ?? 0) + 1);
        out(`  ${c.dim('US severe weather alerts:')} ${[...counts].sort((p, q) => q[1] - p[1]).slice(0, 6).map(([t, n]) => `${t} ×${n}`).join(', ')}`);
      }
      for (const h of r.result) out(`  ${h.level === 'Red' ? c.red('RED   ') : c.yellow('orange')} ${c.gray(h.to.slice(0, 10))} ${c.bold(trunc(h.name, 50))} ${c.dim(trunc(`${h.type}${h.countries ? ` · ${h.countries}` : ''}${h.severity ? ` · ${h.severity}` : ''}`, 90))}${h.current ? '' : c.dim(' (ended)')}`);
      printSources(r);
    });
  },
  async podcast(o, a) {
    const subject = need(a, 1, 'subject');
    const r = await o.podcast(subject, a.flags.pick !== undefined ? Number(a.flags.pick) : undefined);
    emit(a, r, () => {
      const { episodes, picked, transcript: t } = r.result;
      out(c.bold(`Podcasts about ${subject} · ${episodes.length} recent episodes`));
      for (const [i, e] of episodes.entries()) out(`  ${e === picked ? c.green('▶') : ' '} ${String(i).padStart(2)} ${c.gray(e.date.slice(0, 10))} ${trunc(`${e.show}: ${e.title}`, 100)}`);
      if (t) printTranscript(t);
      else if (picked) out(c.yellow(`\n  could not transcribe: ${r.provenance.at(-1)?.note ?? 'error'}`));
      out(c.dim('\n  pick another with --pick <n>'));
      printSources(r);
    });
  },
  async listen(o, a) {
    const url = need(a, 1, 'audio or video file URL').split(' ')[0]!;
    const r = await o.listen(url, typeof a.flags.about === 'string' ? a.flags.about : '');
    emit(a, r, () => {
      if (!r.result) out(c.yellow(`could not transcribe: ${r.provenance.at(-1)?.note ?? 'error'}`));
      else printTranscript(r.result);
      printSources(r);
    });
  },
  async exposure(o, a) {
    const r = await o.exposure(need(a, 1, 'domain'));
    emit(a, r, () => {
      const e = r.result;
      out(c.bold(`Exposure · ${e.domain}`) + c.dim(`  ${e.hostsChecked} hosts checked, ${e.resolved} IPs`));
      for (const x of e.ips) {
        out(`  ${x.ip.padEnd(16)} ${x.cdn ? c.dim(x.cdn.padEnd(18)) : c.yellow('direct'.padEnd(18))} ports ${x.ports.join(',') || '-'}${x.vulns.length ? c.red(`  ${x.vulns.length} CVEs: ${x.vulns.slice(0, 4).join(', ')}`) : ''}`);
        if (x.exploited?.length && !x.cdn) out(c.red(`                   exploited in the wild (CISA KEV): ${x.exploited.slice(0, 6).join(', ')}`));
        if (x.network) out(c.dim(`                   ${trunc(`${x.network.origin ?? '?'}${x.network.country ? ` · ${x.network.country}` : ''}${x.network.rpki ? ` · RPKI ${x.network.rpki}` : ''}${x.network.abuse.length ? ` · abuse ${x.network.abuse[0]}` : ''}`, 100)}`));
        out(c.dim(`                   ${trunc(x.hosts.join(', '), 100)}`));
      }
      if (e.exploited?.length) out(c.red(`\n  ${e.exploited.length} CVE(s) on direct machines are being exploited in the wild: ${e.exploited.slice(0, 8).join(', ')}`));
      if (e.unusualPorts.length) out(c.yellow(`\n  non-web ports on direct machines: ${e.unusualPorts.slice(0, 10).map((p) => `${p.ip}:${p.port}`).join(', ')}`));
      out(c.dim('\n  Ports and CVEs on CDN edges describe the CDN, not the company.'));
      printSignals(r.signals);
      printSources(r);
    });
  },
  async social(o, a) {
    const q = need(a, 1, 'subject');
    const platforms = typeof a.flags.only === 'string' ? (a.flags.only.split(',') as ('x' | 'reddit' | 'tiktok' | 'bluesky')[]) : undefined;
    const r = await o.pulse(q, platforms);
    emit(a, r, () => {
      const p = r.result;
      out(c.bold(`Social pulse · ${q} · ${p.posts} posts`) + c.dim(`  ${Object.entries(p.byPlatform).map(([k, v]) => `${k} ${v}`).join(' · ')}`));
      if (p.acceleration != null) out(`  Reddit pace, last 6h vs earlier: ${p.acceleration >= 3 ? c.red(`${p.acceleration.toFixed(1)}x`) : `${p.acceleration.toFixed(1)}x`}`);
      else out(c.dim('  Reddit pace: not measurable (newest posts span less than a day)'));
      out(c.bold('\nMost engaged'));
      for (const x of p.top) out(`  ${c.cyan(x.platform.padEnd(7))} ${String(x.engagement).padStart(7)}  ${c.gray(x.date.slice(0, 10))} ${trunc(`${x.author}: ${x.text.replace(/\s+/g, ' ')}`, 90)}`);
      out(c.bold('\nLatest'));
      for (const x of p.latest.slice(0, 5)) out(`  ${c.cyan(x.platform.padEnd(7))} ${c.gray(x.date.slice(0, 16).replace('T', ' '))} ${trunc(`${x.author}: ${x.text.replace(/\s+/g, ' ')}`, 90)}`);
      printSources(r);
    });
  },
  async calendar(o, a) {
    const r = await o.calendar(Number(a.pos[1] ?? a.flags.days ?? 14) || 14);
    emit(a, r, () => {
      out(c.bold(`Catalysts ${r.result.from} to ${r.result.to} · ${r.result.items.length} items`) + c.dim('  (★ = watched company or open forecast)'));
      let day = '';
      for (const i of r.result.items) {
        if (i.date !== day) out(`\n  ${c.bold(i.date)}`), (day = i.date);
        const kind = i.kind === 'earnings' ? c.cyan('earnings') : i.kind === 'macro' ? c.yellow('macro   ') : i.kind === 'ipo' ? c.green('ipo     ') : i.kind === 'regulation' ? c.magenta('rule    ') : c.blue('market  ');
        out(`    ${i.watched ? c.yellow('★') : ' '} ${kind} ${trunc(i.title, 80)}${i.detail ? c.dim(`  ${trunc(i.detail, 70)}`) : ''}`);
      }
      printSources(r);
    });
  },
  async connect(o, a) {
    const text = need(a, 1, 'two things, e.g. oculon connect Nvidia to "Jensen Huang"');
    const [x, y] = text.split(/\s+(?:to|and|->)\s+/i);
    if (!x || !y) throw new UsageError('write it as: oculon connect <A> to <B>');
    const r = o.connect(x, y, Number(a.flags.depth ?? 6) || 6);
    emit(a, r, () => {
      if (!r.path) return out(`${c.yellow('no connection')}: ${r.note ?? ''} ${c.dim(`(${r.explored} nodes explored)`)}`);
      out(c.bold(`${x} → ${y}: ${r.path.length - 1} hop(s)`));
      for (const [i, s] of r.path.entries()) {
        const via = s.via ? c.dim(`${s.via.direction === 'out' ? '──' : '<─'}${s.via.rel}${s.via.direction === 'out' ? '─>' : '──'} `) : '';
        out(`  ${i === 0 ? '  ' : '  '}${via}${c.bold(trunc(s.name, 80))} ${c.gray(s.kind)}${s.via ? c.dim(`  via ${s.via.source}`) : ''}`);
      }
    });
  },
  async resolve(o, a) {
    const r = o.resolveEntities();
    emit(a, r, () => {
      out(c.bold(`Entity resolution · ${r.checked} named entities checked, ${r.linked.length} new same_as link(s)`));
      for (const l of r.linked) out(`  ${l.a} ${c.dim('=')} ${l.b} ${c.dim(`(${l.why})`)}`);
    });
  },
  async feedback(o, a) {
    const sub = a.pos[1];
    if (sub === 'useful' || sub === 'noise') {
      const r = o.feedback(need(a, 2, 'signal id'), sub);
      if (!r) throw new Error('no stored signal with that id (see `oculon signals --json`)');
      return emit(a, r, () => out(`Marked ${sub}: ${r.title} ${c.gray(r.module)}`));
    }
    const st = o.feedbackStats();
    const base = Number(process.env.TELEGRAM_ALERT_MIN_SCORE ?? 70);
    emit(a, st, () => {
      if (!st.length) return out('No votes yet. Tap Useful or Noise under a Telegram alert, or run `oculon feedback useful|noise <signal-id>`.');
      out(c.bold(`Feedback · base alert bar ${base}`));
      for (const m of st) out(`  ${m.module.padEnd(12)} ${c.green(`${m.useful} useful`)}  ${c.red(`${m.noise} noise`)}  ${c.dim('→')} alert bar ${c.bold(base + m.shift)}`);
    });
  },
  async live(o, a) {
    const minutes = Number(a.flags.minutes ?? 30) || 30;
    const log = (m: string) => out(c.dim(`${new Date().toISOString().slice(11, 19)} ${m}`));
    out(`${c.bold('Live streams')} Wikipedia edits + Bluesky posts for ${minutes} min ${c.dim('(Bluesky surges need ~20 min of history first; Ctrl+C to stop)')}`);
    const m = await o.live({ log, onSignals: (s) => printSignals(s, 5) });
    const status = setInterval(() => log(`seen ${m.stats.wikiEdits} wiki edits, ${m.stats.posts} posts, ${m.stats.signals} signal(s)`), 5 * 60_000);
    await new Promise((r) => setTimeout(r, minutes * 60_000));
    clearInterval(status);
    m.stop();
    emit(a, m.stats, () => out(c.bold(`Done: ${m.stats.wikiEdits} wiki edits, ${m.stats.posts} posts, ${m.stats.signals} signal(s).`)));
  },
  async brief(o, a) {
    const b = await o.brief({ refresh: a.flags.refresh === true || a.flags.refresh === 'true', ...(typeof a.flags.lang === 'string' ? { lang: a.flags.lang } : {}) });
    emit(a, b, () => out(b.markdown));
  },
  async quota(o, a) {
    const q = o.quota();
    emit(a, q, () => {
      if (!q.length) return out('No metered API calls today.');
      out(c.bold(`API usage today (UTC)`));
      for (const r of q) out(`  ${r.source.padEnd(18)} ${String(r.used).padStart(6)}${r.budget ? ` / ${r.budget}${r.used >= r.budget ? c.red('  reached') : r.used >= r.budget * 0.8 ? c.yellow('  near limit') : ''}` : c.dim('  (no budget)')}`);
    });
  },
  async entity(o, a) {
    const e = o.entity(need(a, 1, 'entity id'));
    emit(a, e, () => {
      if (!e.entity) return out(`No entity ${a.pos[1]}. Ids look like org:nvidia, domain:openai.com, aircraft:a835af.`);
      out(c.bold(`${e.entity.kind}: ${e.entity.name}`));
      for (const n of e.neighbors.slice(0, 40)) out(`  ${n.direction === 'out' ? '→' : '←'} ${c.cyan(n.rel.padEnd(16))} ${n.kind}: ${trunc(n.name, 90)}`);
    });
  },
  async forecast(o, a) {
    const sub = a.pos[1];
    if (sub === 'auto') {
      const r = await o.autoForecast();
      return emit(a, r, () => {
        out(c.bold(`Auto forecasts · ${r.result.created.length} new`));
        for (const p of r.result.created) out(`  ${c.gray(p.id)} ${p.question}\n     "${p.outcome}" model ${c.bold(pct(p.pModel))} vs market ${pct(p.pMarket)} ${c.dim(p.rationale)}`);
        for (const s of r.result.skipped) out(c.dim(`  skipped: ${s}`));
        if (!r.result.created.length && !r.result.skipped.length) out(c.dim('  no market swing was corroborated by another source right now'));
      });
    }
    if (sub === 'resolve') {
      const r = await o.resolveForecasts();
      return emit(a, r, () => {
        out(c.bold(`Checked ${r.result.checked} open forecasts, ${r.result.resolved.length} resolved`));
        for (const p of r.result.resolved) out(`  ${p.question}: ${p.result ? 'YES' : 'NO'} · brier ${p.brierModel?.toFixed(3)} vs market ${p.brierMarket?.toFixed(3)}`);
      });
    }
    if (sub === 'score') {
      const s = o.scoreboard();
      return emit(a, s, () => {
        out(c.bold(`Track record · ${s.total} forecasts, ${s.open} open, ${s.resolved} resolved`));
        out(`  Brier model ${s.brierModel?.toFixed(4) ?? 'n/a'} vs market ${s.brierMarket?.toFixed(4) ?? 'n/a'} ${c.dim('(lower is better)')}`);
        out(`  skill vs market ${s.skill == null ? c.dim('n/a until something resolves') : c.bold(pct(s.skill))} · beat the market ${s.beatMarket}/${s.resolved}`);
      });
    }
    if (sub === 'list') {
      const list = o.forecasts('all', 100);
      return emit(a, list, () => {
        for (const p of list) out(`  ${c.gray(p.id)} ${pct(p.pModel).padStart(4)} vs ${pct(p.pMarket).padStart(4)} ${p.batchId ? c.green('stamped') : c.dim('unstamped')} ${p.result == null ? 'open' : `resolved ${p.result ? 'YES' : 'NO'}`}  ${trunc(p.question, 70)}`);
        if (!list.length) out(c.dim('  no forecasts yet'));
      });
    }
    const slug = need(a, 1, 'market slug (or auto | resolve | score | list)');
    const p = Number(a.flags.p);
    if (!Number.isFinite(p)) throw new UsageError('missing --p <probability between 0 and 1>');
    const r = await o.forecast(slug, p, typeof a.flags.why === 'string' ? a.flags.why : '');
    emit(a, r, () => out(`${c.bold('Recorded')} ${c.gray(r.result.id)}\n  ${r.result.question}\n  "${r.result.outcome}" you ${c.bold(pct(r.result.pModel))} vs market ${pct(r.result.pMarket)}\n  run \`oculon proof stamp\` to timestamp it on Bitcoin`));
  },
  async proof(o, a) {
    const sub = a.pos[1];
    if (sub === 'stamp') {
      const r = await o.stampProofs();
      return emit(a, r, () => {
        const b = r.result.batch;
        if (!b) return out(r.result.reason ?? 'nothing stamped');
        out(`${c.bold(`Stamped ${b.size} forecast(s)`)} in ${c.gray(b.id)}\n  merkle root ${b.root}\n  calendars ${b.receipts.map((x) => x.calendar.replace('https://', '')).join(', ')}\n  ${c.dim('Bitcoin confirmation usually takes a few hours; then run `oculon proof verify <id>`.')}`);
      });
    }
    if (sub === 'verify') {
      const r = await o.verifyProof(need(a, 2, 'forecast id'));
      return emit(a, r, () => {
        const v = r.result;
        const col = v.status === 'VERIFIED' ? c.green : v.status === 'PENDING' ? c.yellow : c.red;
        out(`${c.bold(v.predictionId)} ${col(c.bold(v.status))}`);
        for (const s of v.steps) out(`  - ${s}`);
        if (v.bitcoin) out(c.green(`  anchored in Bitcoin block ${v.bitcoin.height} (${v.bitcoin.time})`));
      });
    }
    throw new UsageError('usage: oculon proof stamp | oculon proof verify <forecast-id>');
  },
  async serve(o, a) {
    const { createWebServer } = await import('../web/server.js');
    const port = Number(a.flags.port ?? process.env.PORT ?? 4747);
    // --host 0.0.0.0 (or HOST) exposes the server beyond this machine; --public (or OCULON_PUBLIC=1) is then required
    // so only the overview, docs and a read-only API are open. The dashboard needs OCULON_ADMIN_TOKEN.
    const host = String(a.flags.host ?? process.env.HOST ?? '127.0.0.1');
    const publicMode = Boolean(a.flags.public) || process.env.OCULON_PUBLIC === '1';
    if (host !== '127.0.0.1' && host !== 'localhost' && !publicMode) {
      throw new UsageError('serving beyond localhost needs --public (or OCULON_PUBLIC=1), so private data and paid APIs stay locked');
    }
    const log = (m: string) => out(c.dim(`${new Date().toISOString().slice(11, 19)} ${m}`));
    // --telegram runs the bot in the same process; the dashboard's schedule then feeds its alerts and brief.
    let bot: import('../telegram.js').TelegramBot | null = null;
    if (a.flags.telegram || process.env.OCULON_TELEGRAM === '1') {
      const { TelegramBot } = await import('../telegram.js');
      bot = new TelegramBot({
        token: process.env.TELEGRAM_BOT_TOKEN ?? '',
        allowedChats: (process.env.TELEGRAM_ALLOWED_CHATS ?? '').split(',').map((s) => s.trim()).filter(Boolean),
        alertMinScore: Number(process.env.TELEGRAM_ALERT_MIN_SCORE ?? 70),
        watchMinutes: 0,
        scheduleMinutes: Number(a.flags.watch ?? 0),
        oculon: o,
        log: (m) => log(`telegram ${m}`),
      });
      void bot.start().catch((e) => log(`telegram stopped: ${(e as Error).message}`));
    }
    createWebServer({
      port,
      host,
      publicMode,
      oculon: o,
      watchMinutes: Number(a.flags.watch ?? 0),
      log,
      ...(bot
        ? {
            onSignals: async (s) => {
              const n = await bot!.pushAlerts(s);
              if (n) log(`telegram alerts sent: ${n}`);
            },
            onBrief: async (md) => {
              await bot!.pushBrief(md);
            },
            onReport: async (file) => {
              await bot!.pushReport(file, 'Weekly Oculon report');
            },
            onPersonal: async (d) => {
              const n = await bot!.pushPersonal(d);
              if (n) log(`telegram monitor messages: ${n}`);
            },
          }
        : {}),
    });
    if (a.flags.live) {
      await o.live({
        log,
        ...(bot
          ? {
              onSignals: async (s) => {
                const n = await bot!.pushAlerts(s);
                if (n) log(`telegram alerts sent: ${n}`);
              },
            }
          : {}),
      });
    }
    out(`${c.bold('Oculon dashboard')} http://${host}:${port}${publicMode ? c.dim('  (public mode)') : ''}${a.flags.watch ? c.dim(`  (schedule every ${a.flags.watch} min)`) : ''}${bot ? c.dim('  + Telegram bot') : ''}${a.flags.live ? c.dim('  + live streams') : ''}`);
    await new Promise(() => {});
  },
  async doctor(o, a) {
    const checks: { name: string; ok: boolean; detail: string }[] = [];
    const [major, minor] = process.versions.node.split('.').map(Number) as [number, number];
    checks.push({ name: 'node', ok: major > 22 || (major === 22 && minor >= 13), detail: `v${process.versions.node} (needs 22.13+)` });
    checks.push({ name: 'database', ok: true, detail: process.env.OCULON_DB || join(oculonHome(), 'oculon.db') });
    checks.push({ name: 'OCULON_CONTACT', ok: Boolean(process.env.OCULON_CONTACT), detail: process.env.OCULON_CONTACT ? 'set (SEC EDGAR enabled)' : 'not set (SEC EDGAR off, optional)' });
    checks.push({ name: 'GITHUB_TOKEN', ok: Boolean(process.env.GITHUB_TOKEN), detail: process.env.GITHUB_TOKEN ? 'set' : 'not set (60 requests/hour, optional)' });
    const KEYS: [string, string[]][] = [
      ['LLM (ask)', ['GROQ_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'NVIDIA_API_KEY', 'OPENROUTER_API_KEY']],
      ['web search', ['TAVILY_API_KEY', 'EXA_API_KEY', 'JINA_API_KEY', 'FIRECRAWL_API_KEY']],
      ['news', ['GNEWS_API_KEY', 'GUARDIAN_API_KEY', 'NYT_API_KEY']],
      ['markets', ['FINNHUB_API_KEY', 'FRED_API_KEY', 'COINGECKO_API_KEY']],
      ['on-chain', ['ZERION_API_KEY', 'ETHERSCAN_API_KEY', 'WEBACY_API_KEY', 'HELIUS_API_KEY', 'ROBINHOOD_PUBLIC_RPC_URL']],
      ['companies', ['ADZUNA_APP_KEY', 'COURTLISTENER_TOKEN', 'COMPANIES_HOUSE_API_KEY', 'BRANDFETCH_API_KEY']],
      ['web security', ['URLSCAN_API_KEY', 'SAFE_BROWSING_KEY', 'ABUSECH_AUTH_KEY']],
      ['threat intel', ['ABUSEIPDB_API_KEY', 'OTX_API_KEY', 'IPINFO_TOKEN', 'VIRUSTOTAL_API_KEY']],
      ['phone', ['NUMVERIFY_API_KEY']],
      ['fact checks', ['GOOGLE_API_KEY']],
      ['social/research', ['YOUTUBE_API_KEY', 'BLUESKY_APP_PASSWORD', 'OPENALEX_API_KEY']],
      ['air quality', ['OPENAQ_API_KEY']],
    ];
    for (const [group, names] of KEYS) {
      const set = names.filter((n) => process.env[n]?.trim());
      checks.push({ name: group, ok: set.length > 0, detail: `${set.length}/${names.length} keys set${set.length < names.length ? ` (missing: ${names.filter((n) => !set.includes(n)).join(', ')})` : ''}` });
    }
    const probes: [string, string][] = [
      ['wikimedia', 'https://wikimedia.org/api/rest_v1/metrics/pageviews/top/en.wikipedia/all-access/2026/01/01'],
      ['hackernews', 'https://hn.algolia.com/api/v1/search?tags=front_page&hitsPerPage=1'],
      ['polymarket', 'https://gamma-api.polymarket.com/markets?limit=1'],
      ['gdelt', 'https://api.gdeltproject.org/api/v2/doc/doc?query=test&mode=artlist&maxrecords=1&format=json'],
      ['crt.sh', 'https://crt.sh/?q=example.com&output=json'],
      ['github', 'https://api.github.com/rate_limit'],
      ['arxiv', 'https://export.arxiv.org/api/query?search_query=all:test&max_results=1'],
      ['adsb.lol', 'https://api.adsb.lol/v2/hex/000000'],
      ['nasa-eonet', 'https://eonet.gsfc.nasa.gov/api/v3/events?limit=1'],
      ['nasa-gibs', 'https://gibs.earthdata.nasa.gov/wms/epsg4326/best/wms.cgi?SERVICE=WMS&REQUEST=GetCapabilities&VERSION=1.3.0'],
      ['usgs', 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/significant_hour.geojson'],
      ['opentimestamps', 'https://a.pool.opentimestamps.org/'],
      ['blockstream', 'https://blockstream.info/api/blocks/tip/height'],
      ['nominatim', 'https://nominatim.openstreetmap.org/status'],
    ];
    const t0 = Date.now();
    const results = await Promise.all(
      probes.map(async ([name, url]) => {
        const s = Date.now();
        try {
          const res = await fetch(url, { method: 'GET', headers: { 'user-agent': 'Oculon doctor' }, signal: AbortSignal.timeout(20_000) });
          await res.body?.cancel();
          return { name, ok: res.status < 500 && res.status !== 429, detail: `HTTP ${res.status} in ${Date.now() - s} ms` };
        } catch (e) {
          return { name, ok: false, detail: (e as Error).name === 'TimeoutError' ? 'timeout' : (e as Error).message };
        }
      }),
    );
    checks.push(...results);
    void o;
    emit(a, checks, () => {
      out(c.bold(`oculon doctor · v${VERSION}`));
      for (const ch of checks) out(`  ${ch.ok ? c.green('ok  ') : c.yellow('warn')} ${ch.name.padEnd(16)} ${c.dim(ch.detail)}`);
      out(c.dim(`\n${checks.filter((x) => !x.ok).length} warning(s), probes took ${Date.now() - t0} ms`));
    });
  },
};

/** Nearest command name by edit distance, when it is close enough to be a typo. */
export function closest(word: string, options: string[]): string | null {
  const d = (x: string, y: string) => {
    const row = Array.from({ length: y.length + 1 }, (_, i) => i);
    for (let i = 1; i <= x.length; i++) {
      let prev = row[0]!;
      row[0] = i;
      for (let j = 1; j <= y.length; j++) {
        const tmp = row[j]!;
        row[j] = Math.min(row[j]! + 1, row[j - 1]! + 1, prev + (x[i - 1] === y[j - 1] ? 0 : 1));
        prev = tmp;
      }
    }
    return row[y.length]!;
  };
  let best: string | null = null;
  let bestD = Infinity;
  for (const o of options) {
    const dist = o.startsWith(word) && word.length >= 3 ? 0.5 : d(word.toLowerCase(), o);
    if (dist < bestD) (best = o), (bestD = dist);
  }
  return bestD <= Math.max(1, Math.floor(word.length / 3)) ? best : null;
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const a = parseArgs(argv);
  const cmd = a.pos[0];
  if (a.flags.version || cmd === 'version') return out(VERSION), 0;
  // `oculon help calendar` or `oculon calendar --help`: just the matching lines.
  const topic = cmd === 'help' ? a.pos[1] : a.flags.help ? cmd : undefined;
  if (topic) {
    const lines = HELP.split('\n').filter((l) => new RegExp(`oculon ${topic}\\b`).test(l));
    out(lines.length ? lines.join('\n') : `No help for "${topic}".\n\n${HELP}`);
    return 0;
  }
  if (!cmd || a.flags.help || cmd === 'help') return out(helpText()), 0;
  if (existsSync('.env')) process.loadEnvFile('.env');

  if (cmd === 'mcp') {
    const { serveStdio } = await import('../mcp.js');
    serveStdio();
    return new Promise(() => {});
  }
  if (cmd === 'telegram') {
    const { TelegramBot } = await import('../telegram.js');
    const bot = new TelegramBot({
      token: process.env.TELEGRAM_BOT_TOKEN ?? '',
      allowedChats: (process.env.TELEGRAM_ALLOWED_CHATS ?? '').split(',').map((s) => s.trim()).filter(Boolean),
      alertMinScore: Number(process.env.TELEGRAM_ALERT_MIN_SCORE ?? 70),
      watchMinutes: Number(process.env.TELEGRAM_WATCH_MINUTES ?? 15),
      log: (m) => out(c.dim(`${new Date().toISOString().slice(11, 19)} ${m}`)),
    });
    await bot.start();
    return 0;
  }

  if (ONCHAIN_COMMANDS.has(cmd) && !onchainEnabled()) {
    out(c.dim(ONCHAIN_PAUSED_MESSAGE));
    return 1;
  }
  const run = COMMANDS[cmd];
  if (!run) {
    const near = closest(cmd, [...Object.keys(COMMANDS), 'mcp', 'telegram', 'help', 'version']);
    out(`${c.red('Unknown command')}: ${cmd}${near ? `. Did you mean ${c.bold(`oculon ${near}`)}?` : ''}`);
    out(c.dim('Run `oculon help` for every command, or `oculon tour` to get started.'));
    return 2;
  }
  const o = new Oculon();
  try {
    await run(o, a);
    return 0;
  } catch (e) {
    if (e instanceof UsageError) {
      out(`${c.red('usage')}: ${e.message.replace(/^usage:\s*/i, '')}. See \`oculon help\`.`);
      return 2;
    }
    out(`${c.red('error')}: ${(e as Error).message}`);
    return 1;
  } finally {
    if (cmd !== 'serve') o.close();
  }
}
