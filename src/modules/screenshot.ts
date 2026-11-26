/**
 * Screenshot check: upload a screenshot of a chat, email, SMS, web page, ad or social post.
 *   Gemini (free key) only reads the image: it transcribes the visible text verbatim and lists the links,
 *   handles, phone numbers, amounts and brand names it sees, and names the kind of screen. It gives no verdict.
 *   The verdict comes from the existing scam check, run in code on the transcribed text (patterns, every
 *   link through the URL check, the sender's domain).
 */
import type { Ctx } from '../core/context.js';
import { key } from '../core/keys.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { extractParts, scamCheck, type ScamCheck } from './scam.js';

export type ScreenKind = 'chat' | 'email' | 'sms' | 'web page' | 'ad' | 'social post' | 'other';
const KINDS: ScreenKind[] = ['chat', 'email', 'sms', 'web page', 'ad', 'social post', 'other'];

export interface ScreenshotCheck {
  name: string;
  bytes: number;
  mime: string;
  /** True when the image was read; false when the reader failed (see notes and provenance). */
  read: boolean;
  screen: ScreenKind | null;
  sender: string | null;
  text: string;
  items: { links: { url: string; defanged: string }[]; handles: string[]; phones: string[]; emails: string[]; amounts: string[]; brands: string[] };
  verdict: ScamCheck['verdict'] | null;
  risk: number | null;
  reasons: string[];
  patterns: ScamCheck['patterns'];
  linkChecks: ScamCheck['links'];
  advice: string[];
  explanation: string | null;
  notes: string[];
}

export const MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024;
/**
 * Gemini models tried in order. gemini-2.5-flash first; its free tier allows only about 20 requests a day,
 * so when it answers 429 (quota), 503 (busy) or 404 (retired) the next free model is tried.
 * Override the whole list with OCULON_SCREENSHOT_MODELS (comma separated).
 */
export const MODELS = () => (process.env.OCULON_SCREENSHOT_MODELS || 'gemini-2.5-flash,gemini-3.5-flash,gemini-3.5-flash-lite').split(',').map((m) => m.trim()).filter((m) => /^[\w.-]+$/.test(m)).slice(0, 4);

/** The image type from its first bytes: png, jpeg or webp. Anything else is null. */
export function imageMime(b: Buffer): 'image/png' | 'image/jpeg' | 'image/webp' | null {
  if (b.length >= 8 && b.readUInt32BE(0) === 0x89504e47 && b.readUInt32BE(4) === 0x0d0a1a0a) return 'image/png';
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (b.length >= 12 && b.toString('latin1', 0, 4) === 'RIFF' && b.toString('latin1', 8, 12) === 'WEBP') return 'image/webp';
  return null;
}

/** A link written so it cannot be clicked or auto-linked: hxxps://example[.]com/path. */
export function defang(url: string): string {
  return url.replace(/^http(s?):\/\//i, 'hxxp$1://').replace(/\./g, '[.]');
}

const PROMPT = `You are a transcription tool. Read this screenshot and report only what is visibly written in it.
Return JSON with these fields:
- "screen": what kind of screen this is, one of: chat, email, sms, web page, ad, social post, other.
- "sender": the sender name, number, address or handle shown at the top of the message or post, or "" if none is visible.
- "text": all visible text, transcribed verbatim in reading order, one line per line on screen. Keep spelling mistakes as they are, skip emoji, and copy URLs exactly as written. Leave out phone status bar text (clock, battery, signal).
- "links": every URL or domain name visible, exactly as written.
- "handles": every @handle, username or channel name visible.
- "phones": every phone number visible, exactly as written.
- "emails": every email address visible.
- "amounts": every amount of money or crypto visible, exactly as written (e.g. "$2.99", "0.5 ETH").
- "brands": every company, bank, app or brand name visible in text or logos.
Do not judge whether it is a scam, do not add advice, do not guess text you cannot read. Use empty strings and empty lists when nothing is there.`;

const SCHEMA = {
  type: 'OBJECT',
  properties: {
    screen: { type: 'STRING', enum: KINDS },
    sender: { type: 'STRING' },
    text: { type: 'STRING' },
    links: { type: 'ARRAY', items: { type: 'STRING' } },
    handles: { type: 'ARRAY', items: { type: 'STRING' } },
    phones: { type: 'ARRAY', items: { type: 'STRING' } },
    emails: { type: 'ARRAY', items: { type: 'STRING' } },
    amounts: { type: 'ARRAY', items: { type: 'STRING' } },
    brands: { type: 'ARRAY', items: { type: 'STRING' } },
  },
  required: ['screen', 'text'],
};

interface Reading { screen: ScreenKind; sender: string; text: string; links: string[]; handles: string[]; phones: string[]; emails: string[]; amounts: string[]; brands: string[] }

const strList = (v: unknown, max = 30): string[] => (Array.isArray(v) ? [...new Set(v.filter((x): x is string => typeof x === 'string').map((x) => x.trim().slice(0, 300)).filter(Boolean))].slice(0, max) : []);

/** Parse Gemini's JSON answer into a reading. Only the listed fields are kept; anything else the model adds is dropped. */
export function parseReading(raw: string): Reading | null {
  let j: Record<string, unknown>;
  try {
    j = JSON.parse(raw.replace(/^\s*```(?:json)?\s*|\s*```\s*$/g, '')) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (!j || typeof j !== 'object' || typeof j.text !== 'string') return null;
  const screen = String(j.screen ?? '').toLowerCase().trim() as ScreenKind;
  return {
    screen: KINDS.includes(screen) ? screen : 'other',
    sender: typeof j.sender === 'string' ? j.sender.trim().slice(0, 200) : '',
    text: j.text.slice(0, 20_000),
    links: strList(j.links), handles: strList(j.handles), phones: strList(j.phones), emails: strList(j.emails), amounts: strList(j.amounts), brands: strList(j.brands),
  };
}

async function readImage(ctx: Ctx, img: Buffer, mime: string, provenance: Provenance[], notes: string[]): Promise<Reading | null> {
  const k = key('GEMINI_API_KEY');
  if (!k) throw new Error('Screenshot Check needs a free Gemini key to read the image: set GEMINI_API_KEY (free at aistudio.google.com)');
  const data = img.toString('base64');
  let lastWhy = 'no model configured';
  for (const model of MODELS()) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
    const body = JSON.stringify({
      contents: [{ role: 'user', parts: [{ text: PROMPT }, { inline_data: { mime_type: mime, data } }] }],
      generationConfig: { temperature: 0, response_mime_type: 'application/json', response_schema: SCHEMA, maxOutputTokens: 8192, ...(model.startsWith('gemini-2.5') ? { thinkingConfig: { thinkingBudget: 0 } } : {}) },
    });
    const r = await ctx.http.postBytes(url, Buffer.from(body), { source: 'gemini-vision', headers: { 'x-goog-api-key': k, 'content-type': 'application/json' }, timeoutMs: 60_000, retries: 0 });
    if (!r.data) {
      lastWhy = r.prov.note ?? r.prov.status;
      provenance.push({ ...r.prov, note: `could not read the image (${model})${r.prov.note ? `: ${r.prov.note}` : ''}` });
      // Quota, overload, retired model or timeout: try the next model. Anything else (bad key, bad request) stops.
      if (/HTTP (429|5\d\d|404)|timeout|fetch failed/i.test(lastWhy)) continue;
      break;
    }
    let j: { candidates?: { content?: { parts?: { text?: string; thought?: boolean }[] }; finishReason?: string }[]; promptFeedback?: { blockReason?: string } } = {};
    try { j = JSON.parse(r.data.toString('utf8')); } catch {}
    const cand = j.candidates?.[0];
    const raw = cand?.content?.parts?.filter((p) => !p.thought).map((p) => p.text ?? '').join('') ?? '';
    const reading = raw ? parseReading(raw) : null;
    if (!reading) {
      const why = j.promptFeedback?.blockReason ? `blocked: ${j.promptFeedback.blockReason}` : cand?.finishReason && cand.finishReason !== 'STOP' ? `stopped: ${cand.finishReason}` : 'no usable answer';
      provenance.push({ ...r.prov, status: 'ERROR', note: `could not read the image (${model}): ${why}` });
      notes.push(`The image reader gave no usable transcription (${why}), so no text was checked.`);
      return null;
    }
    provenance.push({ ...r.prov, note: `text read from the image (${model})${cand?.finishReason === 'MAX_TOKENS' ? ': transcription cut at the length limit' : ''}` });
    if (cand?.finishReason === 'MAX_TOKENS') notes.push('The screenshot holds a lot of text; the transcription was cut at the length limit.');
    return reading;
  }
  notes.push(`The image reader did not answer (${lastWhy}), so no text was checked. Try again later or paste the text into the scam check.`);
  return null;
}

/** Check a screenshot (png, jpeg or webp, up to 8 MB). `name` is only used for display. */
export async function screenshotCheck(ctx: Ctx, file: Buffer, name = 'screenshot'): Promise<ModuleResult<ScreenshotCheck>> {
  if (!file?.length) throw new Error('choose a screenshot first');
  if (file.length > MAX_SCREENSHOT_BYTES) throw new Error(`the image is ${(file.length / 1048576).toFixed(1)} MB; the limit is 8 MB`);
  const mime = imageMime(file);
  if (!mime) throw new Error('only PNG, JPEG and WebP screenshots are read');
  const provenance: Provenance[] = [];
  const notes: string[] = [];
  const out: ScreenshotCheck = {
    name, bytes: file.length, mime, read: false, screen: null, sender: null, text: '',
    items: { links: [], handles: [], phones: [], emails: [], amounts: [], brands: [] },
    verdict: null, risk: null, reasons: [], patterns: [], linkChecks: [], advice: [], explanation: null, notes,
  };
  const reading = await readImage(ctx, file, mime, provenance, notes);
  if (reading) {
    out.read = true;
    out.screen = reading.screen;
    out.sender = reading.sender || null;
    out.text = reading.text;
    // Links: what the reader listed plus what code finds in the transcription.
    const parts = extractParts(reading.text);
    const links = [...new Set([...reading.links, ...parts.urls])].slice(0, 20);
    out.items = {
      links: links.map((url) => ({ url, defanged: defang(url) })),
      handles: reading.handles,
      // The same number written two ways counts once; the form shown on screen is kept.
      phones: [...reading.phones, ...parts.phones].filter((p, i, all) => all.findIndex((q) => q.replace(/\D/g, '') === p.replace(/\D/g, '')) === i).slice(0, 20),
      emails: [...new Set([...reading.emails.map((e) => e.toLowerCase()), ...parts.emails])].slice(0, 20),
      amounts: reading.amounts,
      brands: reading.brands,
    };
    // The scam check reads the transcription; links seen only outside the text (a preview card) and the
    // sender line are added so they are checked too.
    const from = reading.sender && !reading.text.includes(reading.sender) ? [`From: ${reading.sender}`] : [];
    const unseen = reading.links.filter((l) => !reading.text.includes(l));
    const msg = [...from, reading.text, ...unseen].join('\n').trim();
    if (msg.length >= 8) {
      const s = await scamCheck(ctx, msg);
      provenance.push(...s.provenance);
      Object.assign(out, { verdict: s.result.verdict, risk: s.result.risk, reasons: s.result.reasons, patterns: s.result.patterns, linkChecks: s.result.links, advice: s.result.advice, explanation: s.result.explanation });
      if (msg.length > 6000) notes.push('Only the first 6,000 characters of the text were checked.');
    } else {
      notes.push('No readable text was found in the image, so there was nothing to check.');
    }
  }
  return { module: 'screenshot', input: name.slice(0, 120), generatedAt: ctx.now().toISOString(), result: out, signals: [], provenance };
}
