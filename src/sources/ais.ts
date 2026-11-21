/**
 * Live ship positions from aisstream.io (free key, WebSocket). AIS coverage depends on community receivers:
 * strong in Europe and around major straits, thin or absent in some regions. Empty results say so.
 */
import { key } from '../core/keys.js';
import type { Provenance } from '../core/types.js';

export interface Vessel {
  mmsi: number;
  name: string | null;
  lat: number;
  lon: number;
  sog: number | null;
  cog: number | null;
  navStatus: number | null;
  typeCode: number | null;
  destination: string | null;
  callSign: string | null;
  imo: string | null;
  lastSeen: string;
}

/** [[south, west], [north, east]] as aisstream expects. */
export type Box = [[number, number], [number, number]];

export interface AisCollect {
  vessels: Vessel[];
  messages: number;
  seconds: number;
  prov: Provenance;
}

interface AisMessage {
  MessageType?: string;
  error?: string;
  MetaData?: { MMSI: number; ShipName?: string; latitude: number; longitude: number; time_utc?: string };
  Message?: {
    PositionReport?: { Sog?: number; Cog?: number; NavigationalStatus?: number };
    ShipStaticData?: { Type?: number; Destination?: string; CallSign?: string; Name?: string; ImoNumber?: number };
  };
}

export const SHIP_TYPES: [number, number, string][] = [
  [30, 30, 'fishing'],
  [31, 32, 'towing'],
  [35, 35, 'military'],
  [36, 37, 'sailing/pleasure'],
  [40, 49, 'high-speed craft'],
  [50, 59, 'service (pilot, SAR, tug, law enforcement)'],
  [60, 69, 'passenger'],
  [70, 79, 'cargo'],
  [80, 89, 'tanker'],
];

export function shipType(code: number | null): string {
  if (code === null) return 'unknown';
  return SHIP_TYPES.find(([a, b]) => code >= a && code <= b)?.[2] ?? 'other';
}

/** At anchor or moored by AIS status, or effectively stationary. */
export const isStationary = (v: Vessel) => v.navStatus === 1 || v.navStatus === 5 || (v.sog !== null && v.sog < 0.5);

/**
 * Listen for `seconds` and return the latest state per vessel. Never throws; problems are in `prov`.
 * `filterMmsi` follows specific ships anywhere (bounding box can then be the whole world).
 */
export async function collect(boxes: Box[], seconds: number, filterMmsi: number[] = [], wsImpl: typeof WebSocket = WebSocket): Promise<AisCollect> {
  const k = key('AISSTREAM_API_KEY');
  const started = new Date().toISOString();
  const url = 'wss://stream.aisstream.io/v0/stream';
  if (!k) return { vessels: [], messages: 0, seconds, prov: { source: 'aisstream', url, status: 'UNAVAILABLE', fetchedAt: started, note: 'set AISSTREAM_API_KEY to enable' } };
  const vessels = new Map<number, Vessel>();
  let messages = 0;
  let error: string | null = null;
  let confirmed = false;

  await new Promise<void>((resolve) => {
    let ws: WebSocket;
    try {
      ws = new wsImpl(url);
    } catch (e) {
      error = (e as Error).message;
      return resolve();
    }
    let closingByUs = false;
    const timer = setTimeout(() => {
      closingByUs = true;
      ws.close();
    }, seconds * 1000);
    ws.onopen = () =>
      ws.send(
        JSON.stringify({
          APIKey: k,
          BoundingBoxes: boxes,
          FilterMessageTypes: ['PositionReport', 'ShipStaticData'],
          ...(filterMmsi.length ? { FiltersShipMMSI: filterMmsi.map(String) } : {}),
        }),
      );
    ws.onmessage = async (ev: MessageEvent) => {
      const raw = typeof ev.data === 'string' ? ev.data : await (ev.data as Blob).text();
      let m: AisMessage;
      try {
        m = JSON.parse(raw) as AisMessage;
      } catch {
        return;
      }
      if (m.error) {
        error = m.error;
        ws.close();
        return;
      }
      if (m.MessageType === 'SubscriptionConfirmation') {
        confirmed = true;
        return;
      }
      const meta = m.MetaData;
      if (!meta?.MMSI) return;
      messages++;
      const prev = vessels.get(meta.MMSI);
      const pr = m.Message?.PositionReport;
      const sd = m.Message?.ShipStaticData;
      vessels.set(meta.MMSI, {
        mmsi: meta.MMSI,
        name: (meta.ShipName ?? sd?.Name ?? prev?.name ?? '').trim() || null,
        lat: meta.latitude ?? prev?.lat,
        lon: meta.longitude ?? prev?.lon,
        sog: pr?.Sog ?? prev?.sog ?? null,
        cog: pr?.Cog ?? prev?.cog ?? null,
        navStatus: pr?.NavigationalStatus ?? prev?.navStatus ?? null,
        typeCode: sd?.Type ?? prev?.typeCode ?? null,
        destination: sd?.Destination?.trim() || prev?.destination || null,
        callSign: sd?.CallSign?.trim() || prev?.callSign || null,
        imo: sd?.ImoNumber ? String(sd.ImoNumber) : (prev?.imo ?? null),
        lastSeen: meta.time_utc ? new Date(meta.time_utc.replace(' +0000 UTC', 'Z').replace(' ', 'T')).toISOString() : new Date().toISOString(),
      });
    };
    ws.onerror = () => {
      // Closing the stream ourselves at the end of the window can surface as an error event; that is not a failure.
      if (!closingByUs && !messages) error ??= 'websocket error';
    };
    ws.onclose = () => {
      clearTimeout(timer);
      resolve();
    };
  });

  const status = error ? 'ERROR' : 'LIVE';
  const note = error ?? (!confirmed ? 'no subscription confirmation' : messages === 0 ? `no AIS reports in ${seconds}s: no receiver coverage or no traffic here` : undefined);
  return { vessels: [...vessels.values()], messages, seconds, prov: { source: 'aisstream', url, status, fetchedAt: started, ...(note ? { note } : {}) } };
}
