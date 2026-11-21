/**
 * Oculon Telegram bot: long polling against the Bot API, no dependencies.
 * Only chats listed in the allowlist can use it (anyone else gets their chat id and setup instructions).
 * With alerts on, a background loop pushes new high-scoring signals to subscribed chats.
 */
import { readFileSync } from 'node:fs';
import { Oculon, type Signal } from './index.js';
import { alertBar, feedbackStats, recordFeedback, type Verdict } from './modules/feedback.js';
import { describePath } from './modules/connect.js';
import { fmtTime } from './modules/listen.js';
import { startScheduler } from './scheduler.js';

export interface BotOptions {
  token: string;
  /** Chat ids allowed to use the bot. */
  allowedChats: string[];
  oculon?: Oculon;
  fetch?: typeof fetch;
  /** Minimum score for pushed alerts. */
  alertMinScore?: number;
  /** Minutes between background scans for alerts; 0 disables. */
  watchMinutes?: number;
  log?: (m: string) => void;
}

interface Update {
  update_id: number;
  message?: { chat: { id: number; type: string }; text?: string; from?: { username?: string } };
  callback_query?: { id: string; data?: string; from: { id: number }; message?: { chat: { id: number }; message_id: number } };
}

export const esc = (s: unknown) => String(s ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]!);
const pct = (x: number | null | undefined) => (x == null ? 'n/a' : `${Math.round(x * 100)}%`);

export function formatSignal(s: Signal): string {
  const ev = s.evidence
    .slice(0, 3)
    .map((e) => `  • <i>${esc(e.source)}</i>: ${e.url ? `<a href="${esc(e.url)}">${esc(e.text.slice(0, 140))}</a>` : esc(e.text.slice(0, 140))}`)
    .join('\n');
  return `<b>[${Math.round(s.score)}] ${esc(s.title)}</b> <code>${esc(s.module)}</code>${ev ? `\n${ev}` : ''}`;
}

export const HELP = [
  '<b>Oculon</b> — OSINT radar',
  '/ask &lt;question&gt; — AI agent answers using every tool',
  '/radar — what the world is suddenly watching',
  '/signals — latest signals',
  '/dossier &lt;name&gt; — e.g. /dossier Nvidia',
  '/hype &lt;topic&gt; — hype phase of a topic',
  '/footprint &lt;domain&gt; — pre-release footprints',
  '/plane &lt;reg or hex&gt; — track an aircraft',
  '/mil — military air traffic',
  '/events — natural events (NASA)',
  '/lights &lt;place&gt; — night lights vs baseline',
  '/image &lt;place&gt; — satellite image',
  '/wallet &lt;address&gt; — wallet portfolio and risk',
  '/token &lt;address&gt; — token contract check',
  '/space — geomagnetic storms and solar flares',
  '/ships &lt;place&gt; — live vessels near a port (AIS)',
  '/air &lt;place&gt; — PM2.5 air quality',
  '/rh — Robinhood Chain trending and new pools',
  '/case &lt;question&gt; — deep investigation; /case lists, /case 3 opens one',
  '/fence — geofences; /fence add &lt;name&gt; &lt;place&gt;; /fence rm &lt;id&gt;',
  '/markets — Polymarket vs Kalshi and Manifold',
  '/launches &lt;company&gt; — new models, apps, packages',
  '/rewind &lt;YYYY-MM-DD&gt; — what Oculon would have seen that day',
  '/deployer &lt;address&gt; — Robinhood Chain deployer reputation',
  '/scoops — how often Oculon beat the media',
  '/sanctions &lt;wallet|IMO|name&gt; — OFAC screening',
  '/narratives — storylines across days',
  '/health &lt;company&gt; — early-warning score',
  '/impact [place] — people exposed to quakes and storms',
  '/contradict &lt;topic&gt; — conflicting facts across sources',
  '/report — weekly HTML report',
  '/brief — today\'s brief',
  '/watch — list; /watch add &lt;kind&gt; &lt;target&gt;; /watch rm &lt;id&gt;',
  '/score — forecast track record',
  '/sentinel &lt;place&gt; — sharp 10 m satellite image (Sentinel-2); /radar_image &lt;place&gt; sees through clouds',
  '/fires &lt;place&gt; — active fires and hotspots nearby (NASA FIRMS)',
  '/blackout — internet outages and shutdowns right now',
  '/cloud — outages on AWS, Azure, Google Cloud, GitHub, Cloudflare, OpenAI...',
  '/bgp [cc|ASN|IP] — BGP hijacks and route leaks worldwide, or routing of a country, network or IP',
  '/vulns — vulnerabilities newly exploited in the wild (CISA KEV)',
  '/cve &lt;id&gt; — one CVE: severity, exploitation odds, fixes',
  '/regs [query] — US executive orders and rules (Federal Register)',
  '/defi — TVL crashes, stablecoin depegs, hacks',
  '/squawk — aircraft squawking emergency codes now',
  '/filings &lt;phrase&gt; — SEC full-text search, last 30 days',
  '/darkships &lt;place&gt; — vessels that switched off AIS there',
  '/vessel &lt;name|MMSI|IMO&gt; — flag, owners, earlier names, sanctions',
  '/hazards — official orange and red disaster alerts (GDACS)',
  '/podcast &lt;subject&gt; — newest podcast episode about it, transcribed, with quotes',
  '/exposure &lt;domain&gt; — open ports and known CVEs on its servers',
  '/social &lt;subject&gt; — posts on X, Reddit, TikTok, Bluesky right now',
  '/calendar [days] — earnings, macro releases and markets closing soon',
  '/connect &lt;A&gt; to &lt;B&gt; — how two things are linked in the graph',
  '/live — what the live Wikipedia and Bluesky streams flagged',
  '/feedback — how your Useful/Noise votes move each module',
  '/alerts on|off — push new strong signals and the daily brief here',
].join('\n');

export class TelegramBot {
  private offset = 0;
  private running = false;
  private scheduler: { stop: () => void } | null = null;
  readonly oculon: Oculon;
  private readonly doFetch: typeof fetch;
  private readonly log: (m: string) => void;

  constructor(private readonly opts: BotOptions) {
    if (!opts.token) throw new Error('TELEGRAM_BOT_TOKEN is not set');
    this.oculon = opts.oculon ?? new Oculon();
    this.doFetch = opts.fetch ?? fetch;
    this.log = opts.log ?? (() => {});
    const db = this.oculon.ctx.store.db;
    db.exec('CREATE TABLE IF NOT EXISTS telegram_subs (chat_id TEXT PRIMARY KEY, created_at INTEGER NOT NULL)');
    db.exec('CREATE TABLE IF NOT EXISTS telegram_sent (chat_id TEXT NOT NULL, signal_id TEXT NOT NULL, PRIMARY KEY (chat_id, signal_id))');
  }

  /** Bot API call. Never logs the URL, because it contains the token. */
  async call<T = unknown>(method: string, body: Record<string, unknown> | FormData): Promise<T> {
    const isForm = body instanceof FormData;
    const res = await this.doFetch(`https://api.telegram.org/bot${this.opts.token}/${method}`, {
      method: 'POST',
      ...(isForm ? { body } : { body: JSON.stringify(body), headers: { 'content-type': 'application/json' } }),
      signal: AbortSignal.timeout(method === 'getUpdates' ? 45_000 : 30_000),
    });
    const j = (await res.json().catch(() => ({ ok: false, description: `HTTP ${res.status}` }))) as { ok: boolean; result?: T; description?: string };
    if (!j.ok) throw new Error(`telegram ${method}: ${j.description ?? res.status}`);
    return j.result as T;
  }

  /** Send HTML text, split under Telegram's 4096-character limit at line breaks. */
  async send(chatId: string | number, html: string): Promise<void> {
    const parts: string[] = [];
    let cur = '';
    for (const line of html.split('\n')) {
      if (cur.length + line.length + 1 > 3900) {
        parts.push(cur);
        cur = '';
      }
      cur += (cur ? '\n' : '') + line;
    }
    if (cur) parts.push(cur);
    for (const p of parts) await this.call('sendMessage', { chat_id: chatId, text: p, parse_mode: 'HTML', disable_web_page_preview: true });
  }

  async sendDocument(chatId: string | number, file: string, caption: string): Promise<void> {
    const form = new FormData();
    form.set('chat_id', String(chatId));
    form.set('caption', caption.slice(0, 1000));
    form.set('document', new Blob([readFileSync(file)], { type: 'text/html' }), file.split(/[\\/]/).pop() ?? 'report.html');
    await this.call('sendDocument', form);
  }

  /** Send a report file to every subscribed chat. */
  async pushReport(file: string, caption: string): Promise<number> {
    const subs = (this.oculon.ctx.store.db.prepare('SELECT chat_id FROM telegram_subs').all() as { chat_id: string }[]).map((r) => r.chat_id).filter((c) => this.allowed(c));
    for (const chat of subs) await this.sendDocument(chat, file, caption);
    return subs.length;
  }

  async sendPhoto(chatId: string | number, file: string, caption: string): Promise<void> {
    const form = new FormData();
    form.set('chat_id', String(chatId));
    form.set('caption', caption.slice(0, 1000));
    form.set('photo', new Blob([readFileSync(file)], { type: 'image/png' }), 'image.png');
    await this.call('sendPhoto', form);
  }

  allowed(chatId: string): boolean {
    return this.opts.allowedChats.includes(chatId);
  }

  /** Turn one command into a reply. Exposed for tests. */
  async respond(chatId: string, text: string): Promise<{ html?: string; photo?: { file: string; caption: string }; document?: { file: string; caption: string } }> {
    const [rawCmd = '', ...rest] = text.trim().split(/\s+/);
    const cmd = rawCmd.toLowerCase().replace(/@.*$/, '');
    const arg = rest.join(' ').slice(0, 200);
    const o = this.oculon;
    const needArg = (example: string) => ({ html: `Usage: ${esc(cmd)} ${esc(example)}` });

    switch (cmd) {
      case '/start':
      case '/help':
        return { html: HELP };
      case '/radar': {
        const r = await o.radar();
        return { html: r.signals.length ? `<b>Radar</b>: ${r.signals.length} signals\n\n${r.signals.slice(0, 8).map(formatSignal).join('\n\n')}` : 'Radar: nothing stands out right now.' };
      }
      case '/signals': {
        const s = o.signals(10);
        return { html: s.length ? s.map(formatSignal).join('\n\n') : 'No signals yet. Try /radar.' };
      }
      case '/dossier': {
        if (!arg) return needArg('Nvidia');
        const r = await o.dossier(arg);
        const d = r.result;
        const lines = [
          `<b>${esc(d.wikipedia?.title ?? d.query)}</b>${d.wikipedia?.description ? ` — ${esc(d.wikipedia.description)}` : ''}`,
          d.wikipedia?.spike ? `Wikipedia readers ${d.wikipedia.spike.toFixed(1)}× usual` : '',
          ...d.markets.slice(0, 3).map((m) => `market: ${esc(m.question)} — ${pct(m.prices[0])}`),
          '',
          ...d.timeline.slice(0, 8).map((t) => `${esc(t.date.slice(0, 10))} <i>${esc(t.source)}</i> ${esc(t.text.slice(0, 120))}`),
          ...(r.signals.length ? ['', ...r.signals.map(formatSignal)] : []),
        ];
        return { html: lines.filter((l, i, a) => l !== '' || a[i - 1] !== '').join('\n') };
      }
      case '/hype': {
        if (!arg) return needArg('ai agent');
        const r = await o.hype(arg);
        const d = r.result;
        return { html: `<b>${esc(d.topic)}: ${esc(d.phase)}</b>\n${esc(d.summary)}` };
      }
      case '/footprint': {
        if (!arg) return needArg('openai.com');
        const r = await o.footprint(arg);
        const d = r.result;
        const top = d.findings.slice(0, 10).map((f) => `[${f.score}] ${esc(f.kind)} <a href="${esc(f.url)}">${esc(f.value.slice(0, 90))}</a> (${esc(f.firstSeen.slice(0, 10))})`);
        return { html: `<b>${esc(d.domain)}</b>, last ${d.windowDays} days: ${d.counts.subdomain} subdomains, ${d.counts.page} pages, ${d.counts.repo} repos\n${top.join('\n') || 'nothing new'}` };
      }
      case '/plane': {
        if (!arg) return needArg('N628TS');
        const t = (await o.aircraft(arg)).result;
        return {
          html: [
            `<b>${esc(t.info?.registration ?? t.query)}</b> ${esc([t.info?.manufacturer, t.info?.type].filter(Boolean).join(' '))}`,
            t.info?.owner ? `owner: ${esc(t.info.owner)}` : '',
            `status: ${esc(t.status)}${t.state?.altFt != null && t.status === 'AIRBORNE' ? ` at ${t.state.altFt} ft` : ''}`,
            t.place ? `${esc(t.place.relation)} ${esc(t.place.airport)} (${t.place.km} km)` : '',
            t.change ? `<b>${esc(t.change)}</b>` : '',
          ]
            .filter(Boolean)
            .join('\n'),
        };
      }
      case '/mil': {
        const r = await o.military();
        const d = r.result;
        const regions = d.regions.slice(0, 8).map((g) => `${g.count} near ${esc(g.label)}${g.notable.length ? ` — ${g.notable.map((n) => esc(n.role)).join(', ')}` : ''}`);
        return { html: `<b>Military air</b>: ${d.withPosition} aircraft with position\n${regions.join('\n')}${r.signals.length ? `\n\n${r.signals.slice(0, 4).map(formatSignal).join('\n\n')}` : ''}` };
      }
      case '/events': {
        const r = await o.naturalEvents();
        const ev = r.result.events.slice(0, 10).map((e) => `${e.severity ? `[${e.severity}] ` : ''}${esc(e.title)}${e.why ? ` — ${esc(e.why)}` : ''}`);
        return { html: `<b>Natural events</b> (NASA EONET)\n${ev.join('\n') || 'none open'}` };
      }
      case '/lights': {
        if (!arg) return needArg('Gaza Strip');
        const d = (await o.nightLights(arg)).result;
        return { html: `<b>${esc(d.place.name)}</b>\nnight lights: <b>${esc(d.verdict)}</b>${d.ratio ? ` (${d.ratio >= 1 ? '+' : ''}${Math.round((d.ratio - 1) * 100)}%)` : ''}\n${d.recent.length} recent nights vs ${d.baseline.length} baseline nights, newest ${esc(d.latestDate ?? 'n/a')}` };
      }
      case '/image': {
        if (!arg) return needArg('Kyoto');
        const r = await o.satelliteImage(arg);
        if (!r.result.file) return { html: `No image for ${esc(arg)} on ${esc(r.result.date)}.` };
        return { photo: { file: r.result.file, caption: `${r.result.place.name} — ${r.result.date} (NASA MODIS true color)` } };
      }
      case '/ask': {
        if (!arg) return needArg('why is Nvidia in the news?');
        const r = await o.ask(arg);
        return { html: `${esc(r.answer)}\n\n<i>${r.steps.length} tool call(s), ${esc([...new Set(r.providers)].join(', '))}. AI-written from tool results; check the sources.</i>` };
      }
      case '/wallet': {
        if (!arg) return needArg('0x…');
        const w = (await o.wallet(arg)).result;
        return {
          html: [
            `<b>${esc(w.address)}</b>`,
            w.portfolio ? `portfolio $${Math.round(w.portfolio.totalUsd).toLocaleString('en-US')} (Zerion)` : '',
            ...(w.portfolio?.top.slice(0, 5).map((t) => `  ${esc(t.symbol)} $${Math.round(t.valueUsd).toLocaleString('en-US')}`) ?? []),
            w.solana ? `${w.solana.sol.toFixed(3)} SOL, ${w.solana.tokens} token accounts` : '',
            w.firstSeen ? `first tx ${esc(w.firstSeen.slice(0, 10))} (${w.ageDays} days)` : '',
            w.robinhood ? `Robinhood Chain: ${w.robinhood.balanceEth.toFixed(4)} ETH, ${w.robinhood.txCount} txs` : '',
            `risk: ${w.labels.length ? esc(w.labels.join(', ')) : 'no GoPlus labels'}${w.riskScore != null ? `, Webacy ${w.riskScore}` : ''}`,
          ]
            .filter(Boolean)
            .join('\n'),
        };
      }
      case '/token': {
        if (!arg) return needArg('0x…');
        const t = (await o.token(arg.split(' ')[0]!, arg.split(' ')[1] ?? 'eth')).result;
        return { html: `<b>${esc(t.security?.symbol || t.address)}: ${esc(t.verdict)}</b>\n${t.reasons.map((x) => `• ${esc(x)}`).join('\n')}${t.market ? `\nprice ${t.market.priceUsd} · mcap $${Math.round(t.market.marketCapUsd ?? 0).toLocaleString('en-US')}` : ''}` };
      }
      case '/space': {
        const s = (await o.spaceWeather()).result;
        return { html: `<b>Space weather: ${esc(s.stormLevel)}</b>\nKp now ${s.kpNow ?? '?'}, max 24h ${s.kpMax24h ?? '?'}${s.strongestFlare ? `\nstrongest flare (7d) ${esc(s.strongestFlare.maxClass)} at ${esc(s.strongestFlare.maxTime.slice(0, 16))}Z` : ''}` };
      }
      case '/ships': {
        if (!arg) return needArg('Port of Rotterdam');
        const d = (await o.ships(arg, 30)).result;
        if (!d.total) return { html: `No AIS reports near ${esc(d.place.name)} in ${d.seconds}s (no receiver coverage there, or no traffic).` };
        const types = Object.entries(d.byType).sort((x, y) => y[1] - x[1]).slice(0, 5).map(([t, n]) => `${esc(t)} ${n}`).join(', ');
        return { html: `<b>${esc(d.place.name)}</b>\n${d.total} vessels in ${d.seconds}s · ${d.moving} moving · ${d.stationary} anchored/moored\n${types}` };
      }
      case '/air': {
        if (!arg) return needArg('London');
        const d = (await o.airQuality(arg)).result;
        return { html: `<b>${esc(d.place.name)}</b>\nPM2.5 ${d.median != null ? `${d.median.toFixed(0)} µg/m³ · ${esc(d.category)}` : 'no fresh stations within 25 km'}\n${d.stations.map((s) => `${esc(s.name)}: ${s.value}`).join('\n')}` };
      }
      case '/rh': {
        const r = (await o.robinhood()).result;
        const fmt = (p: { pool: { name: string; liquidityUsd: number; change24h: number | null }; flags: string[] }) =>
          `${esc(p.pool.name)} · liq $${Math.round(p.pool.liquidityUsd).toLocaleString('en-US')}${p.pool.change24h != null ? ` · ${p.pool.change24h.toFixed(0)}%` : ''}${p.flags.length ? ` · <i>${esc(p.flags[0]!)}</i>` : ''}`;
        return {
          html: `<b>Robinhood Chain</b>${r.stats ? ` · ${r.stats.transactionsToday.toLocaleString('en-US')} txs today` : ''}\n\n<b>Trending</b>\n${r.trending.slice(0, 6).map(fmt).join('\n')}\n\n<b>New pools</b>\n${r.fresh.slice(0, 6).map(fmt).join('\n')}`,
        };
      }
      case '/case': {
        if (!arg) {
          const list = await o.caseList();
          return { html: list.length ? list.map((k) => `#${k.id} ${esc(k.question.slice(0, 80))} <i>(${k.report?.confidence ?? '-'}, ${k.report?.findings.length ?? 0} findings${k.watch ? ', watching' : ''})</i>`).join('\n') : 'No cases yet. /case &lt;question&gt; opens one.' };
        }
        if (/^\d+$/.test(arg)) {
          const k = await o.caseGet(Number(arg));
          return { html: k?.markdown ? markdownToTelegram(k.markdown) : `No case #${esc(arg)}.` };
        }
        const m = /^watch\s+(\d+)(\s+off)?$/.exec(arg);
        if (m) return { html: (await o.caseWatch(Number(m[1]), !m[2])) ? `Case #${m[1]} watch ${m[2] ? 'off' : 'on'}.` : `No case #${m[1]}.` };
        await this.send(chatId, `Investigating: <i>${esc(arg)}</i>\nThis takes 1-3 minutes.`);
        const r = await o.caseInvestigate({ question: arg });
        return { html: markdownToTelegram(r.case.markdown ?? '') };
      }
      case '/sanctions': {
        if (!arg) return needArg('0x… | IMO 1234567 | exact name');
        const d = (await o.sanctions(arg)).result;
        return { html: `<b>${esc(d.query.slice(0, 60))}: ${esc(d.verdict)}</b> <i>(OFAC SDN, ${d.listSize.toLocaleString('en-US')} entries)</i>${d.hits.map((h) => `\n• ${esc(h.kind)}: ${esc(h.entry.name)} [${esc(h.entry.program)}]${h.detail ? ` — ${esc(h.detail)}` : ''}`).join('')}` };
      }
      case '/narratives': {
        const list = await o.narratives(14);
        return { html: list.length ? `<b>Narratives</b>\n${list.slice(0, 12).map((n) => `${esc(n.name)} — ${n.daily[6]} today, ${n.total} total <i>(${esc(n.phase.toLowerCase())})</i>`).join('\n')}` : 'No narratives yet; they are built every 6 hours.' };
      }
      case '/health': {
        if (!arg) return needArg('Nvidia');
        const d = (await o.health(arg)).result;
        return { html: `<b>${esc(d.company)} health: ${d.score}/100</b>${d.change !== null ? ` (${d.change >= 0 ? '+' : ''}${d.change} vs 7-day avg)` : ''}\n${d.parts.map((p) => `${p.points > 0 ? '+' : ''}${p.points} ${esc(p.name)}: ${esc(p.why)}`).join('\n')}` };
      }
      case '/impact': {
        const r = (await o.impact(arg || undefined, 50)).result;
        if (!r.impacts.length) return { html: 'No M6+ earthquakes or severe storms right now. Try /impact Tokyo' };
        return { html: r.impacts.slice(0, 4).map((i) => `<b>${esc(i.event)}</b>\n~${i.exposedPopulation.toLocaleString('en-US')} people in listed places within ${i.radiusKm} km${i.settlements.length ? `: ${esc(i.settlements.slice(0, 3).map((s) => s.name).join(', '))}` : ' (open sea or remote)'}`).join('\n\n') };
      }
      case '/contradict': {
        if (!arg) return needArg('Anthropic IPO');
        await this.send(chatId, `Reading sources on <i>${esc(arg)}</i>…`);
        const d = (await o.contradictions(arg)).result;
        return { html: d.contradictions.length ? `<b>${d.contradictions.length} contradiction(s) on ${esc(d.topic)}</b>\n${d.contradictions.slice(0, 5).map((x) => `• <b>${esc(x.about)}</b>\nA: ${esc(x.claimA.slice(0, 160))} (<a href="${esc(x.sourceA)}">source</a>)\nB: ${esc(x.claimB.slice(0, 160))} (<a href="${esc(x.sourceB)}">source</a>)`).join('\n')}` : `${d.sourcesRead.length} sources read on ${esc(d.topic)}: no conflicting facts.` };
      }
      case '/report': {
        const r = await o.report(7);
        return { document: { file: r.file, caption: `Oculon report, last 7 days: ${r.counts.signals} signals, ${r.counts.narratives} narratives, ${r.counts.cases} case files` } };
      }
      case '/scoops': {
        const b = o.scoops();
        const best = b.best.slice(0, 5).map((s) => `+${s.leadHours}h ${esc(s.subject)} (${esc(s.mediaSource ?? '')})`);
        return { html: `<b>First to Know</b>\n${b.checked} checked · ${b.covered} covered by media · Oculon first ${b.oculonFirst} · media first ${b.mediaFirst}${b.medianLeadHours !== null ? ` · median ${b.medianLeadHours}h` : ''}${best.length ? `\n${best.join('\n')}` : ''}` };
      }
      case '/deployer': {
        if (!arg) return needArg('0x… (token or deployer on Robinhood Chain)');
        const d = (await o.robinhoodDeployer(arg)).result;
        return { html: `<b>Deployer ${esc(d.deployer.slice(0, 12))}…: ${esc(d.verdict)}</b>\n${esc(d.reasons.join('; '))}\n${d.tokens.slice(0, 8).map((t) => `${esc(t.symbol ?? '?')} liq $${t.reserveUsd.toLocaleString('en-US')}${t.dead ? ' (dead)' : ''}`).join('\n')}` };
      }
      case '/markets': {
        const r = (await o.markets()).result;
        if (!r.comparisons.length) return { html: `Checked ${r.checked} Polymarket markets: no exact match on Kalshi or Manifold right now.` };
        return { html: `<b>Market cross-check</b>\n${r.comparisons.slice(0, 8).map((x) => `${x.gapPp}pp · PM ${Math.round(x.polymarket.probability * 100)}% vs ${esc(x.other.venue)} ${Math.round(x.other.probability * 100)}% · ${esc(x.polymarket.question.slice(0, 80))}`).join('\n')}` };
      }
      case '/launches': {
        if (!arg) return needArg('OpenAI');
        const d = (await o.launches(arg)).result;
        return { html: `<b>Launch radar: ${esc(arg)}</b> (${d.items.length} in ${d.windowDays} days)\n${d.items.slice(0, 12).map((i) => `${esc(i.date.slice(0, 10))} ${esc(i.kind)} <a href="${esc(i.url)}">${esc(i.title.slice(0, 70))}</a>`).join('\n')}` };
      }
      case '/rewind': {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(arg)) return needArg('2026-11-12');
        const d = (await o.rewind(arg)).result;
        return { html: `<b>Time machine: ${esc(d.date)}</b>\n${d.fused.filter((f) => f.sources.some((s) => s !== 'guardian')).slice(0, 8).map((f) => `[${f.score}] ${esc(f.title.slice(0, 80))} <i>(${esc(f.sources.join('+'))})</i>`).join('\n')}` };
      }
      case '/fence': {
        const [sub, name, ...rest] = arg.split(/\s+/);
        if (sub === 'add') {
          if (!name || !rest.length) return needArg('add hormuz Strait of Hormuz');
          const f = await o.fenceAddAround(name, rest.join(' '), 100);
          return { html: `Fence #${f.id} <b>${esc(f.name)}</b> watching ${esc(f.kinds.join(', '))}. New activity inside arrives with /alerts on.` };
        }
        if (sub === 'rm') return { html: o.fenceRemove(Number(name)) ? `Removed fence #${esc(name)}.` : `No fence #${esc(name)}.` };
        const list = o.fenceList();
        return { html: list.length ? list.map((f) => `#${f.id} <b>${esc(f.name)}</b> ${esc(f.kinds.join(','))}${f.lastRun ? ` <i>(checked ${esc(f.lastRun.slice(0, 16))}Z)</i>` : ''}`).join('\n') : 'No fences. /fence add hormuz Strait of Hormuz' };
      }
      case '/brief': {
        const b = await o.brief();
        return { html: markdownToTelegram(b.markdown) };
      }
      case '/watch': {
        const [sub, kind, ...rest] = arg.split(/\s+/);
        if (sub === 'add') {
          if (!kind || !rest.length) return needArg('add company Nvidia');
          const w = o.watchAdd(kind, rest.join(' '));
          return { html: `Watching #${w.id} ${esc(w.kind)} <b>${esc(w.target)}</b>. Changes arrive with /alerts on.` };
        }
        if (sub === 'rm') return { html: o.watchRemove(Number(kind)) ? `Removed #${esc(kind)}.` : `No watch item #${esc(kind)}.` };
        const list = o.watchList();
        return { html: list.length ? list.map((w) => `#${w.id} ${esc(w.kind)} <b>${esc(w.label ?? w.target)}</b>${w.lastRun ? ` <i>(checked ${esc(w.lastRun.slice(0, 16))}Z)</i>` : ''}`).join('\n') : 'Watchlist is empty. /watch add company Nvidia' };
      }
      case '/score': {
        const s = o.scoreboard();
        return { html: `<b>Forecasts</b>: ${s.total} total, ${s.open} open, ${s.resolved} resolved\nBrier model ${s.brierModel?.toFixed(3) ?? 'n/a'} vs market ${s.brierMarket?.toFixed(3) ?? 'n/a'}\nskill vs market: ${s.skill == null ? 'n/a' : pct(s.skill)}` };
      }
      case '/sentinel':
      case '/radar_image': {
        if (!arg) return needArg('Port of Rotterdam');
        const r = await o.sentinel(arg, { kind: cmd === '/radar_image' ? 'radar' : 'optical' });
        const s = r.result.shots[0]!;
        if (!s.file) return { html: `No ${s.kind === 'radar' ? 'radar' : 'clear'} image for ${esc(s.place.name)} between ${s.from} and ${s.to} (${esc(r.provenance.at(-1)?.note ?? 'no data')}).` };
        return { photo: { file: s.file, caption: `${s.place.name.split(',').slice(0, 2).join(',')} · Sentinel-${s.kind === 'radar' ? '1 radar' : '2, 10 m'} · ${s.from} to ${s.to}` } };
      }
      case '/fires': {
        if (!arg) return needArg('Los Angeles');
        const r = await o.fires(arg);
        const f = r.result;
        if (!f.place) return { html: 'Place not found.' };
        const rows = f.clusters.slice(0, 8).map((c) => `• ${c.count} hotspot(s), ${c.frp} MW at <a href="https://firms.modaps.eosdis.nasa.gov/map/#d:24hrs;@${c.lon.toFixed(3)},${c.lat.toFixed(3)},11z">${c.lat.toFixed(3)}, ${c.lon.toFixed(3)}</a>, last ${esc(c.last.slice(0, 16).replace('T', ' '))} UTC`);
        return { html: `<b>Fires near ${esc(f.place.name.split(',')[0])}</b>, last ${f.days} day(s): ${f.hotspots.length} hotspots (${f.high} high confidence)\n${rows.join('\n') || 'none detected'}` };
      }
      case '/darkships': {
        if (!arg) return needArg('Gulf of Guinea');
        const r = await o.darkShips(arg);
        const d = r.result;
        if (!d.place) return { html: 'Place not found.' };
        const rows = d.gaps.slice(0, 10).map((g) => `• <a href="${esc(g.url)}">${esc(g.vessel)}</a>${g.flag ? ` (${esc(g.flag)})` : ''} dark ${g.hours} h, moved ${g.km} km, back ${esc(g.on.slice(0, 10))}`);
        return { html: `<b>AIS switched off near ${esc(d.place.name.split(',')[0])}</b>, last ${d.days} days: ${d.total}\n${rows.join('\n') || 'none in Global Fishing Watch data'}` };
      }
      case '/vessel': {
        if (!arg) return needArg('EVER GIVEN');
        const r = await o.vessel(arg);
        if (!r.result.length) return { html: 'No vessel found.' };
        return { html: r.result.slice(0, 3).map((v) => `<b>${esc(v.name ?? '?')}</b> IMO ${esc(v.imo ?? '?')} MMSI ${esc(v.mmsi ?? '?')} flag ${esc(v.flag ?? '?')} ${esc(v.types.join('/'))}\nAIS ${esc((v.firstSeen ?? '?').slice(0, 10))} to ${esc((v.lastSeen ?? '?').slice(0, 10))}${v.owners.length ? `\nowners: ${esc(v.owners.slice(0, 3).map((x) => x.name).join(', '))}` : ''}${v.earlierNames.length ? `\nearlier names: ${esc(v.earlierNames.join(', '))}` : ''}${v.sanctions ? `\nOFAC: <b>${esc(v.sanctions)}</b>` : ''}${v.url ? `\n<a href="${esc(v.url)}">track</a>` : ''}`).join('\n\n') };
      }
      case '/cloud': {
        const r = await o.cloud();
        const c = r.result;
        const rows = c.incidents.slice(0, 12).map((i) => `• <b>${esc(i.service)}</b> <i>${esc(i.impact)}</i>: <a href="${esc(i.url)}">${esc(i.title.slice(0, 120))}</a>`);
        return { html: `<b>Service status</b> (${c.checked} platforms)\n${rows.join('\n') || 'No open incidents.'}${c.degraded.length ? `\n\nDegraded: ${esc(c.degraded.map((d) => `${d.service} (${d.indicator})`).join(', '))}` : ''}` };
      }
      case '/bgp': {
        const r = await o.bgp(arg || 'world');
        const { country, asn, ip, incidents } = r.result;
        const inc = incidents
          ? `\n\n<b>Hijacks</b> (confidence 9+): ${incidents.hijacks.filter((h) => h.confidence >= 9 && !h.sameOrg).length} of ${incidents.hijacks.length}\n${incidents.hijacks.filter((h) => h.confidence >= 9 && !h.sameOrg).slice(0, 5).map((h) => `• ${esc(h.hijacker)} took ${esc(h.prefixes.slice(0, 2).join(', '))} from ${esc(h.victims.slice(0, 1).join('') || '?')}${h.ongoing ? ' (ongoing)' : ''}`).join('\n')}\n<b>Route leaks</b>: ${incidents.leaks.length}\n${incidents.leaks.slice(0, 4).map((l) => `• ${esc(l.leaker)}: ${l.prefixes} prefixes${l.finished ? '' : ' (ongoing)'}`).join('\n')}${incidents.attacks ? `\n<b>DDoS targets 24h</b>: ${esc(incidents.attacks.layer7.slice(0, 5).map((x) => `${x.name} ${Math.round(x.share * 100)}%`).join(', '))}` : ''}`
          : '';
        if (ip) return { html: `<b>${esc(ip.ip)}</b> ${esc(ip.prefix ?? '')}\nnetwork ${esc(ip.origins.map((x) => `${x.name} (${x.asn})`).join(', ') || '?')}\nRPKI <b>${esc(ip.rpki ?? 'unknown')}</b> · ${esc([ip.city, ip.country].filter(Boolean).join(', ') || '?')}${ip.abuse.length ? `\nabuse: ${esc(ip.abuse.join(', '))}` : ''}` };
        if (asn) return { html: `<b>${esc(asn.asn)}</b> ${esc(asn.name ?? '')}${asn.visibilityV4 !== null ? `\nvisible to ${Math.round((asn.visibilityV4 ?? 0) * 100)}% of RIPE peers (IPv4), ${asn.prefixesV4} IPv4 / ${asn.prefixesV6} IPv6 prefixes, ${asn.neighbours} neighbours` : ''}${inc}` };
        if (country?.latest && country.baseline) return { html: `<b>${esc(country.country)}</b> routing: ${country.latest.v4} IPv4 prefixes visible now vs ${country.baseline.v4} usual (${country.v4Change != null ? `${(country.v4Change * 100).toFixed(1)}%` : 'n/a'}), ${country.latest.asns} networks${inc}` };
        if (incidents) return { html: `<b>Global routing incidents</b>${inc}` };
        return { html: 'No routing data.' };
      }
      case '/vulns': {
        const r = await o.vulns({ days: Number(arg) || 7 });
        const rows = r.result.kev.slice(0, 12).map((k) => `• <b>${esc(k.cveID)}</b> ${esc(`${k.vendorProject} ${k.product}`)}: ${esc(k.vulnerabilityName.slice(0, 90))}${k.knownRansomwareCampaignUse === 'Known' ? ' <b>ransomware</b>' : ''} (added ${esc(k.dateAdded)})`);
        return { html: `<b>Newly exploited in the wild</b> (CISA KEV, ${r.result.window.from.slice(0, 10)} on)\n${rows.join('\n') || 'none added'}\n\nNew critical CVEs (NVD): ${r.result.criticalCves.length}` };
      }
      case '/cve': {
        if (!arg) return needArg('CVE-2021-44228');
        const d = (await o.cve(arg)).result;
        return { html: `<b>${esc(d.id)}</b> ${d.cvss ? `${d.cvss.score} ${esc(d.cvss.severity)}` : 'no CVSS yet'}${d.kev ? '\n<b>Exploited in the wild (CISA KEV)</b>' : ''}${d.epss ? `\nEPSS ${(d.epss.score * 100).toFixed(1)}% in 30 days` : ''}\n${esc(d.description.slice(0, 500))}${d.packages.length ? `\nfixes: ${esc(d.packages.slice(0, 4).map((p) => `${p.name} ${p.fixed.join('/') || '?'}`).join(', '))}` : ''}` };
      }
      case '/regs': {
        const r = await o.regs(arg ? { query: arg } : {});
        const g = r.result;
        const eo = g.executiveOrders.slice(0, 4).map((d) => `• <b>EO ${esc(d.executiveOrder ?? '')}</b> <a href="${esc(d.url)}">${esc(d.title.slice(0, 120))}</a>`);
        const docs = g.documents.filter((d) => d.significant || d.type === 'Rule').slice(0, 8).map((d) => `• ${esc(d.publicationDate)} <i>${esc(d.type)}</i> <a href="${esc(d.url)}">${esc(d.title.slice(0, 110))}</a>`);
        return { html: `<b>Federal Register</b>${arg ? ` "${esc(arg)}"` : ''}\n${[...eo, ...docs].join('\n') || 'nothing notable'}${g.publicInspection.length ? `\n\n${g.publicInspection.length} documents on public inspection (publish next)` : ''}` };
      }
      case '/defi': {
        const d = (await o.defi()).result;
        const usd = (n: number) => (n >= 1e9 ? `$${(n / 1e9).toFixed(1)}B` : `$${(n / 1e6).toFixed(1)}M`);
        const rows = [
          ...d.tvlDrops.slice(0, 6).map((p) => `• <b>${esc(p.name)}</b> TVL ${p.change1d.toFixed(0)}% in a day (${usd(p.prevTvl)} to ${usd(p.tvl)})`),
          ...d.depegs.slice(0, 4).map((s) => `• <b>${esc(s.symbol)}</b> depeg at $${s.price.toFixed(4)} (${usd(s.circulating)} supply)`),
          ...d.hacks.slice(0, 4).map((h) => `• hack <b>${esc(h.name)}</b> ${usd(h.amount)} (${esc(h.date.slice(0, 10))})`),
        ];
        return { html: `<b>DeFi risk</b>${d.fearGreed ? ` · fear &amp; greed ${d.fearGreed.value} ${esc(d.fearGreed.label)}` : ''}\n${rows.join('\n') || 'nothing alarming'}` };
      }
      case '/squawk': {
        const s = (await o.squawks()).result;
        const rows = s.aircraft.slice(0, 10).map((x) => `• <b>${x.code}</b> ${esc(x.callsign ?? x.hex)} ${esc(x.type ?? '')} ${x.altFt ?? '?'} ft${x.nearestAirport ? `, ${x.nearestAirport.km} km from ${esc(x.nearestAirport.name)}` : ''}`);
        return { html: `<b>Emergency squawks</b>: ${s.total}\n${rows.join('\n') || 'none right now'}` };
      }
      case '/filings': {
        if (!arg) return needArg('cybersecurity incident');
        const f = (await o.filings(arg, { days: 30 })).result;
        const rows = f.hits.slice(0, 10).map((h) => `• ${esc(h.filed)} ${esc(h.form)} <a href="${esc(h.url)}">${esc(h.company.slice(0, 60))}</a>`);
        return { html: `<b>SEC filings mentioning "${esc(arg)}"</b>, 30 days: ${f.total}${f.totalIsLowerBound ? '+' : ''}\n${rows.join('\n')}` };
      }
      case '/blackout': {
        const r = await o.blackout(Number(arg) || 2);
        const rows = r.result.outages.slice(0, 10).map((x) => `• ${x.verified ? '' : '<i>(unverified)</i> '}<b>${esc(x.country ?? '?')}</b>${x.network ? ` ${esc(x.network)}` : ''}${x.cause ? ` – ${esc(x.cause)}` : ''}, since ${esc(x.start.slice(0, 16).replace('T', ' '))}${x.end ? '' : ' (ongoing)'}${x.url ? ` <a href="${esc(x.url)}">source</a>` : ''}`);
        const io = r.result.ioda.slice(0, 5).map((x) => esc(x.name)).join(', ');
        return { html: `<b>Internet outages, last ${r.result.days} days</b>\n${rows.join('\n') || 'none reported'}${io ? `\n\nIODA top countries: ${io}` : ''}` };
      }
      case '/hazards': {
        const r = await o.hazards(Number(arg) || 7);
        const rows = r.result.slice(0, 12).map((h) => `• <b>${h.level === 'Red' ? 'RED' : 'orange'}</b> <a href="${esc(h.url)}">${esc(h.name)}</a>${h.countries ? ` (${esc(h.countries)})` : ''}${h.severity ? `, ${esc(h.severity)}` : ''}`);
        return { html: `<b>GDACS alerts, last ${Number(arg) || 7} days</b>\n${rows.join('\n') || 'none'}` };
      }
      case '/podcast': {
        if (!arg) return needArg('Nvidia');
        const r = await o.podcast(arg);
        const t = r.result.transcript;
        const ep = r.result.picked;
        if (!ep) return { html: 'No podcast episodes found.' };
        if (!t) return { html: `Found <b>${esc(ep.show)}: ${esc(ep.title)}</b> but could not transcribe it (${esc(r.provenance.at(-1)?.note ?? 'error')}).` };
        const quotes = t.mentions.slice(0, 4).map((m) => `• <code>${fmtTime(m.start)}</code> ${esc(m.text.slice(0, 280))}`).join('\n');
        return { html: `<b>${esc(ep.show)}</b>: ${esc(ep.title)} (${esc(ep.date.slice(0, 10))}, ${fmtTime(t.durationSec)})${ep.pageUrl ? ` <a href="${esc(ep.pageUrl)}">listen</a>` : ''}${t.summary ? `\n\n<i>Machine summary:</i> ${esc(t.summary.slice(0, 600))}` : ''}${quotes ? `\n\n<b>Mentions</b>\n${quotes}` : ''}` };
      }
      case '/exposure': {
        if (!arg) return needArg('example.com');
        const r = await o.exposure(arg);
        const e = r.result;
        const rows = e.ips.slice(0, 8).map((x) => `• ${esc(x.ip)} ${x.cdn ? `<i>${esc(x.cdn)}</i> ` : ''}ports ${esc(x.ports.join(', ') || 'none')}${x.vulns.length ? `, <b>${x.vulns.length} CVEs</b>` : ''} (${esc(x.hosts.slice(0, 3).join(', '))})`).join('\n');
        return { html: `<b>Exposure: ${esc(e.domain)}</b>\n${e.hostsChecked} hosts checked, ${e.resolved} IPs, ${e.vulns} known CVEs on non-CDN machines\n${rows}` };
      }
      case '/social': {
        if (!arg) return needArg('Nvidia');
        const r = await o.pulse(arg);
        const p = r.result;
        const plat = Object.entries(p.byPlatform).map(([k, v]) => `${k} ${v}`).join(', ') || 'none';
        const line = (x: (typeof p.top)[number]) => `• <i>${esc(x.platform)}</i> ${esc(x.author)}: <a href="${esc(x.url)}">${esc(x.text.slice(0, 120))}</a> (${x.engagement})`;
        return { html: `<b>Social pulse: ${esc(arg)}</b>\n${p.posts} posts (${esc(plat)})${p.acceleration != null ? `, Reddit pace ${p.acceleration.toFixed(1)}x` : ''}\n\n<b>Most engaged</b>\n${p.top.slice(0, 6).map(line).join('\n')}` };
      }
      case '/calendar': {
        const r = await o.calendar(Number(arg) || 7);
        const items = r.result.items.slice(0, 30);
        if (!items.length) return { html: 'No catalysts found in that window.' };
        let day = '';
        const lines = [`<b>Catalysts ${r.result.from} to ${r.result.to}</b>`];
        for (const i of items) {
          if (i.date !== day) lines.push('', `<b>${i.date}</b>`), (day = i.date);
          lines.push(`${i.watched ? '★ ' : ''}${i.kind}: ${i.url ? `<a href="${esc(i.url)}">${esc(i.title)}</a>` : esc(i.title)}${i.detail ? ` <i>${esc(i.detail)}</i>` : ''}`);
        }
        return { html: lines.join('\n') };
      }
      case '/connect': {
        const [a, b] = arg.split(/\s+(?:to|and|->)\s+/i);
        if (!a || !b) return needArg('Nvidia to Jensen Huang');
        const r = o.connect(a, b);
        return { html: r.path ? `<b>${esc(a)} → ${esc(b)}</b> (${r.path.length - 1} hops)\n${esc(describePath(r.path))}` : esc(r.note ?? 'no path') };
      }
      case '/live': {
        const s = o.signals(200).filter((x) => x.module === 'live').slice(0, 10);
        return { html: s.length ? `<b>Live streams</b>\n\n${s.map(formatSignal).join('\n\n')}` : 'Nothing flagged by the live streams yet. They run inside <code>oculon serve</code>.' };
      }
      case '/feedback': {
        const st = feedbackStats(o.ctx);
        const base = this.opts.alertMinScore ?? 70;
        return { html: st.length ? `<b>Feedback</b> (base alert bar ${base})\n${st.map((m) => `${esc(m.module)}: ${m.useful} useful, ${m.noise} noise → bar ${base + m.shift}`).join('\n')}` : 'No votes yet. Tap Useful or Noise under an alert.' };
      }
      case '/alerts': {
        const on = arg.toLowerCase() !== 'off';
        const db = o.ctx.store.db;
        if (on) db.prepare('INSERT OR IGNORE INTO telegram_subs (chat_id, created_at) VALUES (?, ?)').run(chatId, Date.now());
        else db.prepare('DELETE FROM telegram_subs WHERE chat_id = ?').run(chatId);
        return { html: on ? `Alerts on: signals scoring ${this.opts.alertMinScore ?? 70}+ will be sent here${this.opts.watchMinutes ? ` (scan every ${this.opts.watchMinutes} min)` : ' when the bot runs with a watch interval'}.` : 'Alerts off.' };
      }
      default:
        return { html: `Unknown command. ${HELP}` };
    }
  }

  /** A tap on Useful / Noise under an alert. */
  async handleCallback(q: NonNullable<Update['callback_query']>): Promise<void> {
    const chatId = String(q.message?.chat.id ?? q.from.id);
    const m = /^fb:([un]):(.+)$/.exec(q.data ?? '');
    if (!this.allowed(chatId) || !m) {
      await this.call('answerCallbackQuery', { callback_query_id: q.id }).catch(() => {});
      return;
    }
    const verdict: Verdict = m[1] === 'u' ? 'useful' : 'noise';
    const s = recordFeedback(this.oculon.ctx, m[2]!, verdict, chatId);
    const st = s ? feedbackStats(this.oculon.ctx).find((x) => x.module === s.module) : undefined;
    const base = this.opts.alertMinScore ?? 70;
    await this.call('answerCallbackQuery', {
      callback_query_id: q.id,
      text: s ? `Marked ${verdict}. ${s.module}: ${st?.useful ?? 0} useful, ${st?.noise ?? 0} noise, alert bar ${base + (st?.shift ?? 0)}.` : 'That signal is no longer stored.',
    }).catch(() => {});
    if (s && q.message) {
      await this.call('editMessageReplyMarkup', { chat_id: q.message.chat.id, message_id: q.message.message_id, reply_markup: { inline_keyboard: [[{ text: verdict === 'useful' ? 'Marked useful' : 'Marked noise', callback_data: 'fb:done' }]] } }).catch(() => {});
    }
    this.log(`feedback ${verdict} on ${m[2]}`);
  }

  async handle(u: Update): Promise<void> {
    if (u.callback_query) return this.handleCallback(u.callback_query);
    const m = u.message;
    if (!m?.text) return;
    const chatId = String(m.chat.id);
    if (!this.allowed(chatId)) {
      await this.send(chatId, `This Oculon bot is private. Your chat id is <code>${esc(chatId)}</code>. Add it to TELEGRAM_ALLOWED_CHATS to use the bot.`);
      this.log(`rejected chat ${chatId}`);
      return;
    }
    this.log(`chat ${chatId}: ${m.text.slice(0, 60)}`);
    try {
      const r = await this.respond(chatId, m.text);
      if (r.photo) await this.sendPhoto(chatId, r.photo.file, r.photo.caption);
      if (r.document) await this.sendDocument(chatId, r.document.file, r.document.caption);
      if (r.html) await this.send(chatId, r.html);
    } catch (e) {
      await this.send(chatId, `Error: ${esc((e as Error).message)}`).catch(() => {});
    }
  }

  /** Push signals the chat has not seen yet. Returns how many were sent. */
  async pushAlerts(signals: Signal[]): Promise<number> {
    const db = this.oculon.ctx.store.db;
    const subs = (db.prepare('SELECT chat_id FROM telegram_subs').all() as { chat_id: string }[]).map((r) => r.chat_id).filter((c) => this.allowed(c));
    const min = this.opts.alertMinScore ?? 70;
    let sent = 0;
    for (const chat of subs) {
      for (const s of signals.filter((x) => x.score >= alertBar(this.oculon.ctx, x.module, min))) {
        const res = db.prepare('INSERT OR IGNORE INTO telegram_sent (chat_id, signal_id) VALUES (?, ?)').run(chat, s.id);
        if (!res.changes) continue;
        await this.call('sendMessage', {
          chat_id: chat,
          text: `ALERT ${formatSignal(s)}`.slice(0, 3900),
          parse_mode: 'HTML',
          disable_web_page_preview: true,
          reply_markup: { inline_keyboard: [[{ text: 'Useful', callback_data: `fb:u:${s.id}` }, { text: 'Noise', callback_data: `fb:n:${s.id}` }]] },
        });
        sent++;
      }
    }
    return sent;
  }

  async scanAndAlert(): Promise<number> {
    const results = await Promise.allSettled([this.oculon.radar(), this.oculon.military(), this.oculon.naturalEvents()]);
    const signals = results.flatMap((r) => (r.status === 'fulfilled' ? r.value.signals : []));
    return this.pushAlerts(signals);
  }

  async pollOnce(): Promise<number> {
    const updates = await this.call<Update[]>('getUpdates', { offset: this.offset, timeout: 30, allowed_updates: ['message', 'callback_query'] });
    for (const u of updates) {
      this.offset = u.update_id + 1;
      await this.handle(u);
    }
    return updates.length;
  }

  async start(): Promise<void> {
    this.running = true;
    const me = await this.call<{ username: string }>('getMe', {});
    this.log(`bot @${me.username} running; ${this.opts.allowedChats.length} allowed chat(s)`);
    await this.call('setMyCommands', {
      commands: ['ask', 'case', 'brief', 'report', 'narratives', 'health', 'impact', 'contradict', 'sanctions', 'watch', 'fence', 'markets', 'launches', 'rewind', 'deployer', 'scoops', 'rh', 'ships', 'radar', 'signals', 'dossier', 'hype', 'footprint', 'plane', 'mil', 'events', 'lights', 'image', 'wallet', 'token', 'space', 'air', 'score', 'cloud', 'bgp', 'vulns', 'cve', 'regs', 'defi', 'squawk', 'filings', 'fires', 'sentinel', 'radar_image', 'darkships', 'vessel', 'blackout', 'hazards', 'podcast', 'exposure', 'social', 'calendar', 'connect', 'live', 'feedback', 'alerts'].map((c) => ({ command: c, description: `Oculon ${c}` })),
    }).catch(() => {});
    if (this.opts.watchMinutes && this.opts.watchMinutes > 0) {
      this.scheduler = startScheduler(this.oculon, {
        scanMinutes: this.opts.watchMinutes,
        log: (m) => this.log(`schedule ${m}`),
        onSignals: async (signals) => {
          const n = await this.pushAlerts(signals);
          if (n) this.log(`alerts sent: ${n}`);
        },
        onBrief: async (md) => {
          await this.pushBrief(md);
        },
        onReport: async (file) => {
          await this.pushReport(file, 'Weekly Oculon report');
        },
      });
    }
    while (this.running) {
      try {
        await this.pollOnce();
      } catch (e) {
        this.log(`poll error: ${(e as Error).message}`);
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
  }

  stop(): void {
    this.running = false;
    this.scheduler?.stop();
  }

  /** Send the daily brief to every subscribed chat. Markdown is reduced to Telegram HTML (bold and links). */
  async pushBrief(markdown: string): Promise<number> {
    const subs = (this.oculon.ctx.store.db.prepare('SELECT chat_id FROM telegram_subs').all() as { chat_id: string }[]).map((r) => r.chat_id).filter((c) => this.allowed(c));
    const html = markdownToTelegram(markdown);
    for (const chat of subs) await this.send(chat, html);
    return subs.length;
  }
}

/** Minimal Markdown to Telegram HTML: headings and **bold** to <b>, [text](url) to links; everything else escaped. */
export function markdownToTelegram(md: string): string {
  return md
    .split('\n')
    .map((line) => {
      const heading = /^#{1,3}\s+(.*)$/.exec(line);
      const body = heading ? heading[1]! : line;
      let out = esc(body)
        .replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')
        .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, (_m, t: string, u: string) => `<a href="${u.replace(/"/g, '%22')}">${t}</a>`)
        .replace(/^\s*[-*]\s+/, '• ');
      if (heading) out = `<b>${out}</b>`;
      return out;
    })
    .join('\n');
}
