import { Graph } from './graph.js';
import { Http, type HttpConfig } from './http.js';
import { Store } from './store.js';

export { oculonHome } from './paths.js';

export interface Ctx {
  store: Store;
  http: Http;
  graph: Graph;
  now: () => Date;
}

export interface ContextOptions extends HttpConfig {
  dbPath?: string;
  now?: () => Date;
}

export function createContext(opts: ContextOptions = {}): Ctx {
  const store = new Store(opts.dbPath);
  return {
    store,
    http: new Http(store, opts),
    graph: new Graph(store),
    now: opts.now ?? (() => new Date()),
  };
}

export const DAY_MS = 86_400_000;

/** YYYYMMDD in UTC. */
export function ymd(d: Date): string {
  return d.toISOString().slice(0, 10).replace(/-/g, '');
}

export const enc = encodeURIComponent;
