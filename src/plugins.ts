/**
 * Plugins: drop a .mjs file into ~/.oculon/plugins (or OCULON_PLUGINS) to add tools. Each plugin's tools become
 * CLI commands (`oculon plugin run name.tool`) and MCP tools (`plugin_name_tool`).
 *
 *   export default {
 *     name: 'hn-show',
 *     description: 'Show HN tracker',
 *     tools: [{ name: 'top', description: '...', inputSchema: { type: 'object', properties: {} }, run: async (api, args) => ... }],
 *   };
 *
 * `api` gives cached, rate-limited, quota-counted HTTP (`api.get`), signal saving (`api.signal`), the entity graph
 * (`api.graph.upsert/link`) and `api.now()`. Plugins run with full Node permissions: install only code you trust.
 */
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { oculonHome } from './core/paths.js';
import { signalId } from './core/text.js';
import type { Evidence, Sourced } from './core/types.js';
import type { Oculon } from './index.js';

export interface PluginApi {
  get: <T = unknown>(url: string, opts?: { ttlSec?: number; as?: 'json' | 'text'; headers?: Record<string, string> }) => Promise<Sourced<T>>;
  signal: (s: { title: string; score: number; evidence?: Evidence[]; key?: string }) => void;
  graph: { upsert: (kind: 'topic' | 'org' | 'domain' | 'event', name: string, attrs?: Record<string, unknown>) => string; link: (a: string, b: string, rel: string) => void };
  now: () => Date;
}

export interface PluginTool {
  name: string;
  description: string;
  inputSchema?: Record<string, unknown>;
  run: (api: PluginApi, args: Record<string, unknown>) => Promise<unknown> | unknown;
}

export interface Plugin {
  name: string;
  description?: string;
  version?: string;
  tools: PluginTool[];
  file: string;
}

export function pluginDir(): string {
  return process.env.OCULON_PLUGINS || join(oculonHome(), 'plugins');
}

const NAME = /^[a-z0-9][a-z0-9-]{0,40}$/;

/** Load every valid plugin; invalid ones are reported, never fatal. */
export async function loadPlugins(dir = pluginDir()): Promise<{ plugins: Plugin[]; errors: string[] }> {
  const plugins: Plugin[] = [];
  const errors: string[] = [];
  if (!existsSync(dir)) return { plugins, errors };
  for (const f of readdirSync(dir).filter((x) => x.endsWith('.mjs') || x.endsWith('.js')).sort()) {
    const file = join(dir, f);
    try {
      const mod = (await import(pathToFileURL(file).href)) as { default?: Omit<Plugin, 'file'> };
      const p = mod.default;
      if (!p || !NAME.test(p.name ?? '') || !Array.isArray(p.tools)) throw new Error('default export needs { name (a-z0-9-), tools: [] }');
      const tools = p.tools.filter((t) => NAME.test(t?.name ?? '') && typeof t.run === 'function' && typeof t.description === 'string');
      if (plugins.some((x) => x.name === p.name)) throw new Error(`duplicate plugin name ${p.name}`);
      plugins.push({ ...p, tools, file });
    } catch (e) {
      errors.push(`${f}: ${(e as Error).message}`);
    }
  }
  return { plugins, errors };
}

export function pluginApi(o: Oculon, plugin: string): PluginApi {
  return {
    get: (url, opts = {}) => o.ctx.http.get(url, { source: `plugin:${plugin}`, ttlSec: opts.ttlSec ?? 600, ...(opts.as ? { as: opts.as } : {}), ...(opts.headers ? { headers: opts.headers } : {}) }),
    signal: (s) =>
      o.ctx.graph.saveSignal({
        id: signalId(`plugin-${plugin}`, s.key ?? s.title),
        module: `plugin:${plugin}`,
        title: String(s.title).slice(0, 200),
        score: Math.max(0, Math.min(100, Number(s.score) || 0)),
        evidence: (s.evidence ?? []).slice(0, 10),
        createdAt: o.ctx.now().toISOString(),
      }),
    graph: { upsert: (kind, name, attrs) => o.ctx.graph.upsert(kind, name, attrs), link: (a, b, rel) => o.ctx.graph.link(a, b, rel, `plugin:${plugin}`) },
    now: () => o.ctx.now(),
  };
}

export async function runPluginTool(o: Oculon, ref: string, args: Record<string, unknown> = {}): Promise<unknown> {
  const [pname, tname] = ref.split('.');
  const { plugins } = await loadPlugins();
  const p = plugins.find((x) => x.name === pname);
  const t = p?.tools.find((x) => x.name === tname);
  if (!p || !t) throw new Error(`no plugin tool ${ref}; see \`oculon plugin list\``);
  return t.run(pluginApi(o, p.name), args);
}
