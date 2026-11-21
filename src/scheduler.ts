/**
 * Background schedule shared by the dashboard (`oculon serve --watch`) and the Telegram bot.
 * Intervals are chosen to stay inside free-tier quotas; every task is isolated so one failure
 * never stops the others.
 *
 *   every scan interval (default 15 min): radar, military air, natural events, space weather, Robinhood Chain
 *   every 60 min: watchlist re-check (reports changes only)
 *   every 6 h:    resolve forecasts whose markets settled
 *   once a day:   automatic forecasts + Bitcoin timestamp of new forecasts; daily brief from 07:00 local time
 */
import type { Signal } from './core/types.js';
import type { Oculon } from './index.js';

export interface SchedulerOptions {
  scanMinutes?: number;
  watchMinutes?: number;
  briefHour?: number;
  log?: (m: string) => void;
  onSignals?: (signals: Signal[]) => Promise<void> | void;
  onBrief?: (markdown: string) => Promise<void> | void;
  onReport?: (file: string) => Promise<void> | void;
}

const MIN = 60_000;

export function startScheduler(o: Oculon, opts: SchedulerOptions = {}): { stop: () => void; tick: () => Promise<void> } {
  const log = opts.log ?? (() => {});
  const scanMs = (opts.scanMinutes ?? 15) * MIN;
  const watchMs = (opts.watchMinutes ?? 60) * MIN;
  const last: Record<string, number> = {};
  let running = false;

  const due = (name: string, every: number) => Date.now() - (last[name] ?? 0) >= every;
  const today = () => new Date().toISOString().slice(0, 10);
  const doneToday = (name: string) => o.ctx.store.db.prepare('SELECT 1 FROM scheduler_runs WHERE name = ? AND day = ?').get(name, today()) !== undefined;
  const markToday = (name: string) => o.ctx.store.db.prepare('INSERT OR REPLACE INTO scheduler_runs (name, day, ran_at) VALUES (?, ?, ?)').run(name, today(), Date.now());

  async function task(name: string, fn: () => Promise<Signal[] | void>) {
    const t0 = Date.now();
    try {
      const signals = (await fn()) ?? [];
      last[name] = Date.now();
      log(`${name}: ${signals.length} signal(s) in ${((Date.now() - t0) / 1000).toFixed(0)}s`);
      if (signals.length && opts.onSignals) await opts.onSignals(signals);
    } catch (e) {
      last[name] = Date.now();
      log(`${name} failed: ${(e as Error).message}`);
    }
  }

  async function tick() {
    if (running) return;
    running = true;
    try {
      if (due('scan', scanMs)) {
        await task('radar', async () => (await o.radar()).signals);
        await task('military', async () => (await o.military()).signals);
        await task('events', async () => (await o.naturalEvents()).signals);
        // NASA DONKI and NeoWs change slowly: include them every 3 hours, NOAA every scan.
        const nasa = due('space-nasa', 3 * 60 * MIN);
        await task('space', async () => (await o.spaceWeather(7, { nasa })).signals);
        if (nasa) last['space-nasa'] = Date.now();
        await task('squawk', async () => (await o.squawks()).signals);
        await task('robinhood', async () => (await o.robinhood()).signals);
        if (o.fenceList().length) await task('fences', async () => (await o.fenceCheck()).signals);
        await task('impact', async () => (await o.impact()).signals);
        await task('blackout', async () => (await o.blackout(2)).signals);
        await task('hazards', async () => (await o.hazards(7)).signals);
        await task('cloud', async () => (await o.cloud()).signals);
        last.scan = Date.now();
      }
      if (due('watch', watchMs) && o.watchList().length) await task('watch', async () => (await o.watchRun()).signals);
      if (due('resolve', 6 * 60 * MIN)) await task('resolve', async () => void (await o.resolveForecasts()));
      if (due('scoops', 6 * 60 * MIN)) await task('scoops', async () => void (await o.scoopsCheck(6)));
      if (due('markets', 6 * 60 * MIN)) await task('markets', async () => (await o.markets()).signals);
      if (due('bgp', 60 * MIN)) await task('bgp', async () => (await o.bgp('world')).signals);
      if (due('defi', 60 * MIN)) await task('defi', async () => (await o.defi()).signals);
      if (due('vulns', 6 * 60 * MIN)) await task('vulns', async () => (await o.vulns({ days: 2 })).signals);
      if (due('regs', 6 * 60 * MIN)) await task('regs', async () => (await o.regs({ days: 2 })).signals);
      if (!doneToday('forecast')) {
        await task('auto-forecast', async () => void (await o.autoForecast()));
        await task('stamp', async () => void (await o.stampProofs()));
        markToday('forecast');
      }
      if (due('narratives', 6 * 60 * MIN)) await task('narratives', async () => (await o.narrativesRun()).signals);
      if (!doneToday('health')) {
        for (const w of o.watchList().filter((x) => x.kind === 'company').slice(0, 5)) await task(`health ${w.target}`, async () => (await o.health(w.target)).signals.filter((s) => s.module === 'health'));
        markToday('health');
      }
      // Weekly report on Mondays, sent to Telegram when the bot runs.
      if (new Date().getDay() === 1 && new Date().getHours() >= (opts.briefHour ?? 7) && !doneToday('report')) {
        await task('report', async () => {
          const r = await o.report(7);
          if (opts.onReport) await opts.onReport(r.file);
        });
        markToday('report');
      }
      if (!doneToday('prune')) {
        await task('prune cache', async () => void o.ctx.store.pruneCache(14));
        markToday('prune');
      }
      if (!doneToday('cases')) {
        // Watched cases: at most three per day, they are the most quota-hungry task.
        const watched = (await o.caseList()).filter((k) => k.watch).slice(0, 3);
        for (const k of watched) await task(`case #${k.id}`, async () => (await o.caseInvestigate({ id: k.id })).signals);
        markToday('cases');
      }
      if (new Date().getHours() >= (opts.briefHour ?? 7) && !doneToday('brief')) {
        await task('brief', async () => {
          const b = await o.brief({ refresh: true });
          if (opts.onBrief) await opts.onBrief(b.markdown);
        });
        markToday('brief');
      }
    } finally {
      running = false;
    }
  }

  void tick();
  const timer = setInterval(() => void tick(), MIN);
  return { stop: () => clearInterval(timer), tick };
}
