/**
 * Copernicus Data Space (free account, OAuth client): Sentinel-2 true color at 10 m, and Sentinel-1 radar,
 * which sees through clouds and at night, through the Sentinel Hub Process API.
 * The least cloudy scene in the time window is used. Tokens are kept in memory only.
 */
import type { Ctx } from '../core/context.js';
import { key, missingKey } from '../core/keys.js';
import type { Provenance } from '../core/types.js';

const TOKEN_URL = 'https://identity.dataspace.copernicus.eu/auth/realms/CDSE/protocol/openid-connect/token';
const PROCESS_URL = 'https://sh.dataspace.copernicus.eu/api/v1/process';

let token: { value: string; until: number } | null = null;

async function getToken(ctx: Ctx): Promise<{ value: string | null; prov?: Provenance }> {
  if (token && token.until > Date.now()) return { value: token.value };
  const id = key('COPERNICUS_CLIENT_ID');
  const secret = key('COPERNICUS_CLIENT_SECRET');
  if (!id || !secret) return { value: null, prov: missingKey('copernicus', 'COPERNICUS_CLIENT_ID and COPERNICUS_CLIENT_SECRET') };
  const r = await ctx.http.postBytes(TOKEN_URL, new TextEncoder().encode(new URLSearchParams({ grant_type: 'client_credentials', client_id: id, client_secret: secret }).toString()), {
    source: 'copernicus-auth',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    timeoutMs: 30_000,
  });
  if (!r.data) return { value: null, prov: r.prov };
  try {
    const j = JSON.parse(r.data.toString('utf8')) as { access_token?: string; expires_in?: number };
    if (!j.access_token) return { value: null, prov: { ...r.prov, status: 'ERROR', note: 'no access token' } };
    token = { value: j.access_token, until: Date.now() + Math.max(60, (j.expires_in ?? 600) - 60) * 1000 };
    return { value: token.value };
  } catch {
    return { value: null, prov: { ...r.prov, status: 'ERROR', note: 'invalid token response' } };
  }
}

const TRUE_COLOR = `//VERSION=3
function setup(){return{input:["B02","B03","B04","dataMask"],output:{bands:4}}}
function evaluatePixel(s){return[2.5*s.B04,2.5*s.B03,2.5*s.B02,s.dataMask]}`;

const RADAR = `//VERSION=3
function setup(){return{input:["VV","dataMask"],output:{bands:4}}}
function evaluatePixel(s){var v=Math.max(0,Math.log(0.05/0.02)*0.21+Math.log(Math.max(s.VV,0.0001))*0.21+0.6);return[v,v,v,s.dataMask]}`;

export type SentinelKind = 'optical' | 'radar';

/** [south, north, west, east] box, time window, image width; returns a PNG. */
export async function sentinelImage(ctx: Ctx, box: [number, number, number, number], from: Date, to: Date, kind: SentinelKind = 'optical', width = 1024): Promise<{ png: Buffer | null; prov: Provenance }> {
  const t = await getToken(ctx);
  if (!t.value) return { png: null, prov: t.prov! };
  const [s, n, w, e] = box;
  const latMid = ((s + n) / 2) * (Math.PI / 180);
  const height = Math.max(64, Math.min(2048, Math.round((width * (n - s)) / ((e - w) * Math.cos(latMid)))));
  const body = {
    input: {
      bounds: { bbox: [w, s, e, n], properties: { crs: 'http://www.opengis.net/def/crs/EPSG/0/4326' } },
      data: [
        kind === 'optical'
          ? { type: 'sentinel-2-l2a', dataFilter: { timeRange: { from: from.toISOString(), to: to.toISOString() }, mosaickingOrder: 'leastCC' } }
          : { type: 'sentinel-1-grd', dataFilter: { timeRange: { from: from.toISOString(), to: to.toISOString() }, mosaickingOrder: 'mostRecent' }, processing: { orthorectify: true } },
      ],
    },
    output: { width, height, responses: [{ identifier: 'default', format: { type: 'image/png' } }] },
    evalscript: kind === 'optical' ? TRUE_COLOR : RADAR,
  };
  const r = await ctx.http.postBytes(PROCESS_URL, new TextEncoder().encode(JSON.stringify(body)), {
    source: 'copernicus',
    headers: { authorization: `Bearer ${t.value}`, 'content-type': 'application/json', accept: 'image/png' },
    timeoutMs: 120_000,
  });
  const ok = r.data && r.data.subarray(0, 4).toString('hex') === '89504e47';
  return { png: ok ? r.data : null, prov: ok ? r.prov : { ...r.prov, status: r.prov.status === 'LIVE' ? 'ERROR' : r.prov.status, note: r.prov.note ?? r.data?.toString('utf8').slice(0, 160) } };
}
