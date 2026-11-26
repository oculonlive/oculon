/**
 * Image check: was this picture made by AI, edited, or taken with a camera? Reads the file itself, offline:
 *   - C2PA Content Credentials (JPEG APP11, PNG caBX, WebP C2PA chunk): the app that signed the manifest, the
 *     actions it lists (created, edited, AI-generated), the IPTC digital source type, and the organizations named
 *     in the signing certificates (OpenAI, Adobe, Google, Microsoft, camera makers...).
 *   - IPTC / XMP digital source type (trainedAlgorithmicMedia = made by AI), and AI credit lines.
 *   - Generator parameters that image tools write into PNG text chunks (Stable Diffusion, ComfyUI, NovelAI,
 *     InvokeAI, Midjourney) with the prompt when present.
 *   - EXIF camera make and model, and editing software (Photoshop, GIMP, Canva...).
 * Missing metadata proves nothing: most sites and chat apps strip it. The signature on a C2PA manifest is not
 * verified cryptographically here; the report says which certificates it names.
 */
import { createHash } from 'node:crypto';
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { IMAGE_EDITORS, inflate, jpegMeta, pngMeta } from './doc.js';
import { certNames } from '../core/der.js';

export const IMAGE_MAX_BYTES = 15 * 1024 * 1024;

export interface ImageReport {
  name: string;
  type: 'jpeg' | 'png' | 'webp';
  bytes: number;
  sha256: string;
  verdict: 'AI generated' | 'AI edited' | 'computer generated' | 'edited' | 'camera photo' | 'no provenance found';
  risk: number;
  c2pa: { present: boolean; generator: string | null; actions: string[]; sourceType: string | null; signers: string[] } | null;
  generator: { tool: string; prompt: string | null; settings: string | null } | null;
  camera: string | null;
  software: string | null;
  metadata: Record<string, string>;
  reasons: string[];
  notes: string[];
  advice: string[];
}

const SOURCE_TYPES: Record<string, string> = {
  trainedAlgorithmicMedia: 'made by a generative AI model',
  compositeWithTrainedAlgorithmicMedia: 'edited with generative AI (part of the image is AI)',
  algorithmicMedia: 'made by an algorithm, without a camera',
  digitalCapture: 'taken with a digital camera',
  negativeFilm: 'scanned from film',
  positiveFilm: 'scanned from film',
  print: 'scanned from a print',
  minorHumanEdits: 'camera image with minor edits',
  compositeCapture: 'a composite of camera images',
  composite: 'a composite',
  dataDrivenMedia: 'made from data',
  digitalArt: 'digital art made by a person',
  virtualRecording: 'a recording of a virtual scene',
  screenCapture: 'a screenshot',
};

/** JUMBF bytes holding the C2PA manifest store, from whichever container the image uses. */
export function c2paBytes(b: Buffer, type: ImageReport['type']): Buffer | null {
  const parts: Buffer[] = [];
  if (type === 'jpeg') {
    let i = 2;
    while (i + 4 < b.length && b[i] === 0xff) {
      const m = b[i + 1]!;
      if (m === 0xda || m === 0xd9) break;
      const len = b.readUInt16BE(i + 2);
      // APP11 carries JUMBF: "JP" common identifier, 2-byte instance, 4-byte sequence, then the box.
      if (m === 0xeb && b.toString('latin1', i + 4, i + 6) === 'JP') parts.push(b.subarray(i + 4 + 8, i + 2 + len));
      i += 2 + len;
    }
  } else if (type === 'png') {
    let i = 8;
    while (i + 12 <= b.length) {
      const len = b.readUInt32BE(i);
      const t = b.toString('latin1', i + 4, i + 8);
      if (t === 'caBX') parts.push(b.subarray(i + 8, i + 8 + len));
      if (t === 'IEND') break;
      i += 12 + len;
    }
  } else {
    let i = 12;
    while (i + 8 <= b.length) {
      const t = b.toString('latin1', i, i + 4), len = b.readUInt32LE(i + 4);
      if (t === 'C2PA') parts.push(b.subarray(i + 8, i + 8 + len));
      i += 8 + len + (len & 1);
    }
  }
  const all = Buffer.concat(parts);
  return all.length && all.includes('c2pa') ? all : null;
}

/** CBOR text value right after a text key, e.g. "claim_generator" -> "Adobe_Photoshop/26.0". */
function cborText(buf: Buffer, k: string): string[] {
  const out: string[] = [];
  const keyBytes = Buffer.from(k, 'latin1');
  let at = buf.indexOf(keyBytes);
  while (at >= 0 && out.length < 8) {
    let p = at + keyBytes.length;
    const head = buf[p]!;
    let len = -1;
    if (head >= 0x60 && head <= 0x77) { len = head - 0x60; p += 1; }
    else if (head === 0x78) { len = buf[p + 1]!; p += 2; }
    else if (head === 0x79) { len = buf.readUInt16BE(p + 1); p += 3; }
    if (len > 0 && len < 400) {
      const s = buf.toString('utf8', p, p + len);
      if (/^[\x20-\x7e -￿]+$/.test(s)) out.push(s);
    }
    at = buf.indexOf(keyBytes, at + 1);
  }
  return out;
}

function pngTexts(b: Buffer): Record<string, string> {
  const out: Record<string, string> = {};
  let i = 8;
  while (i + 12 <= b.length) {
    const len = b.readUInt32BE(i);
    const type = b.toString('latin1', i + 4, i + 8);
    const data = b.subarray(i + 8, i + 8 + len);
    if (type === 'tEXt' || type === 'zTXt' || type === 'iTXt') {
      const z = data.indexOf(0);
      const k = data.toString('latin1', 0, z);
      let v = '';
      if (type === 'tEXt') v = data.toString('utf8', z + 1);
      else if (type === 'zTXt') v = inflate(data.subarray(z + 2))?.toString('utf8') ?? '';
      else {
        const rest = data.subarray(z + 1);
        let p = 2; p = rest.indexOf(0, p) + 1; p = rest.indexOf(0, p) + 1;
        v = rest[0] === 1 ? inflate(rest.subarray(p))?.toString('utf8') ?? '' : rest.subarray(p).toString('utf8');
      }
      out[k] = v.slice(0, 20_000);
    }
    if (type === 'IEND') break;
    i += 12 + len;
  }
  return out;
}

function xmpOf(b: Buffer): string {
  const s = b.toString('latin1');
  const a = s.indexOf('<x:xmpmeta');
  if (a < 0) return '';
  const e = s.indexOf('</x:xmpmeta>', a);
  return Buffer.from(s.slice(a, e > a ? e + 12 : a + 60_000), 'latin1').toString('utf8');
}

export async function imageCheck(ctx: Ctx, file: Buffer, name = 'image'): Promise<ModuleResult<ImageReport>> {
  if (!file.length) throw new Error('the file is empty');
  if (file.length > IMAGE_MAX_BYTES) throw new Error('the image is larger than 15 MB');
  const type: ImageReport['type'] | null = file[0] === 0xff && file[1] === 0xd8 ? 'jpeg' : file.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) ? 'png' : file.toString('latin1', 0, 4) === 'RIFF' && file.toString('latin1', 8, 12) === 'WEBP' ? 'webp' : null;
  if (!type) throw new Error('not a JPEG, PNG or WebP image');
  const now = ctx.now().toISOString();
  const reasons: [string, number][] = [];
  const notes: string[] = [];
  const metadata: Record<string, string> = type === 'jpeg' ? jpegMeta(file).meta : type === 'png' ? pngMeta(file).meta : {};
  let verdict: ImageReport['verdict'] = 'no provenance found';

  // Content Credentials.
  let c2pa: ImageReport['c2pa'] = null;
  const jb = c2paBytes(file, type);
  if (jb) {
    const gen = [...cborText(jb, 'claim_generator'), ...cborText(jb, 'name')].find((g) => /[a-z]/i.test(g) && !/^c2pa\.|^(jumbf|self)/i.test(g)) ?? null;
    const actions = [...new Set((jb.toString('latin1').match(/c2pa\.(created|edited|opened|placed|converted|cropped|resized|filtered|color_adjustments|drawing|transcoded|repackaged|removed|published)/g) ?? []))];
    const st = /digitalsourcetype\/([A-Za-z]+)/.exec(jb.toString('latin1'))?.[1] ?? null;
    c2pa = { present: true, generator: gen, actions, sourceType: st ? SOURCE_TYPES[st] ?? st : null, signers: certNames(jb) };
    reasons.push([`carries Content Credentials (C2PA)${gen ? ` written by ${gen}` : ''}${c2pa.signers.length ? `, signed with certificates naming ${c2pa.signers.slice(0, 3).join(', ')}` : ''}`, 0]);
    if (st === 'algorithmicMedia') { verdict = 'computer generated'; reasons.push([`the credentials say it was ${SOURCE_TYPES[st]}`, 40]); }
    else if (st === 'trainedAlgorithmicMedia') { verdict = 'AI generated'; reasons.push([`the credentials say it was ${SOURCE_TYPES[st]}`, 80]); }
    else if (st === 'compositeWithTrainedAlgorithmicMedia') { verdict = 'AI edited'; reasons.push([`the credentials say it was ${SOURCE_TYPES[st]}`, 60]); }
    else if (st === 'digitalCapture' && !actions.some((a) => a !== 'c2pa.created' && a !== 'c2pa.opened')) { verdict = 'camera photo'; reasons.push(['the credentials say it was taken with a camera and list no edits', 0]); }
    if (actions.some((a) => /edited|placed|drawing|filtered|removed|color_adjustments|cropped/.test(a)) && !/^(AI|computer)/.test(verdict)) { verdict = 'edited'; reasons.push([`the credentials list edits: ${actions.filter((a) => a !== 'c2pa.opened').map((a) => a.slice(5)).join(', ')}`, 35]); }
    if (/openai|dall.?e|chatgpt|sora/i.test(`${gen} ${c2pa.signers.join(' ')}`) && verdict === 'no provenance found') { verdict = 'AI generated'; reasons.push(['made by an OpenAI image tool, by its credentials', 80]); }
    if (/firefly|imagen|gemini|bing image|designer|midjourney|meta ai/i.test(`${gen}`) && verdict === 'no provenance found') { verdict = 'AI generated'; reasons.push([`made by ${gen}`, 75]); }
  }

  // IPTC / XMP digital source type.
  const xmp = xmpOf(file);
  const xst = /DigitalSourceType(?:="|>)[^"<]*digitalsourcetype\/([A-Za-z]+)/i.exec(xmp)?.[1];
  if (xst && verdict === 'no provenance found') {
    if (xst === 'algorithmicMedia') { verdict = 'computer generated'; reasons.push([`IPTC metadata says it was ${SOURCE_TYPES[xst]}`, 40]); }
    else if (xst === 'trainedAlgorithmicMedia') { verdict = 'AI generated'; reasons.push([`IPTC metadata says it was ${SOURCE_TYPES[xst]}`, 75]); }
    else if (xst === 'compositeWithTrainedAlgorithmicMedia') { verdict = 'AI edited'; reasons.push([`IPTC metadata says it was ${SOURCE_TYPES[xst]}`, 55]); }
    else reasons.push([`IPTC metadata says it was ${SOURCE_TYPES[xst] ?? xst}`, 0]);
  }
  const credit = /(?:photoshop:Credit|Iptc4xmpCore:CreditLine|dc:creator)[^>]*>(?:\s*<rdf:\w+>\s*<rdf:li[^>]*>)?([^<]{2,120})/i.exec(xmp)?.[1]?.trim();
  if (credit && /made with|generated|google ai|ai generated|imagen|firefly|midjourney/i.test(credit)) {
    if (verdict === 'no provenance found') verdict = 'AI generated';
    reasons.push([`credit line: "${credit}"`, 60]);
  }

  // Generator parameters in PNG text.
  let generator: ImageReport['generator'] = null;
  if (type === 'png') {
    const t = pngTexts(file);
    if (t.parameters) {
      const [prompt, ...rest] = t.parameters.split(/\nNegative prompt:|\nSteps:/);
      const model = /Model: ([^,\n]+)/.exec(t.parameters)?.[1];
      generator = { tool: `Stable Diffusion${model ? ` (${model.trim()})` : ''}`, prompt: prompt?.trim().slice(0, 400) ?? null, settings: /Steps:[^\n]+/.exec(t.parameters)?.[0]?.slice(0, 300) ?? (rest.length ? 'present' : null) };
    } else if (t.workflow || (t.prompt && /class_type/.test(t.prompt))) {
      const texts = [...(t.prompt ?? '').matchAll(/"text":\s*"((?:[^"\\]|\\.){3,400})"/g)].map((m) => m[1]!);
      generator = { tool: 'ComfyUI', prompt: texts[0] ?? null, settings: 'workflow embedded' };
    } else if (/novelai/i.test(t.Software ?? '') || /novelai/i.test(t.Source ?? '')) {
      generator = { tool: 'NovelAI', prompt: t.Description?.slice(0, 400) ?? null, settings: t.Comment ? 'present' : null };
    } else if (t.invokeai_metadata || t['sd-metadata'] || t.Dream) {
      generator = { tool: 'InvokeAI', prompt: /"positive_prompt":\s*"([^"]{1,400})"/.exec(t.invokeai_metadata ?? '')?.[1] ?? null, settings: 'present' };
    } else if (/midjourney/i.test(`${t.Author ?? ''} ${t.Description ?? ''} ${t.Software ?? ''}`) || /Job ID: [0-9a-f-]{36}/.test(t.Description ?? '')) {
      generator = { tool: 'Midjourney', prompt: t.Description?.replace(/\s*Job ID:.*$/s, '').slice(0, 400) ?? null, settings: null };
    }
    if (generator) { verdict = 'AI generated'; reasons.push([`the file holds ${generator.tool} generation settings${generator.prompt ? ' and the prompt' : ''}`, 85]); }
  }
  if (/midjourney|dall.?e|stable diffusion|firefly|leonardo|ideogram|flux|imagen/i.test(`${metadata.software ?? ''} ${metadata['creator tool'] ?? ''} ${xmp.slice(0, 4000)}`) && verdict === 'no provenance found') {
    verdict = 'AI generated'; reasons.push([`the metadata names an AI image tool (${(metadata.software ?? metadata['creator tool'] ?? 'in XMP').slice(0, 60)})`, 70]);
  }

  // Camera and editing software.
  const camera = [metadata.make, metadata.model].filter(Boolean).join(' ').trim() || null;
  const software = metadata.software ?? metadata['creator tool'] ?? null;
  if (software && IMAGE_EDITORS.test(software) && verdict !== 'AI generated') {
    if (verdict !== 'AI edited') verdict = 'edited';
    reasons.push([`saved by an image editor (${software})`, 35]);
  }
  if (metadata['edit history']) reasons.push([`edit history lists ${metadata['edit history']}`, 15]);
  if (camera && verdict === 'no provenance found') { verdict = 'camera photo'; reasons.push([`camera ${camera} recorded in EXIF`, 0]); notes.push('EXIF camera data can be copied into any file; without Content Credentials it is a hint, not proof.'); }
  if (verdict === 'no provenance found') notes.push('No credentials, camera data or AI generator traces. Most social networks and chat apps strip metadata, so this says nothing either way; look for visual signs and find the original source with a reverse image search.');

  const risk = Math.min(100, reasons.reduce((s, [, w]) => s + w, 0));
  const advice = verdict === 'AI generated' || verdict === 'AI edited'
    ? ['Treat it as not a real photo. Do not use it as evidence of an event, a person or a product.']
    : verdict === 'edited' ? ['The image was changed after it was made. Ask for the original file before relying on it.']
      : verdict === 'camera photo' ? ['Camera data looks normal. Still check where and when it was first posted.'] : ['Search for the original (reverse image search) before you trust or share it.'];
  const prov: Provenance[] = [{ source: 'oculon-image', url: 'local', status: 'LIVE', fetchedAt: now, note: 'read from the file itself, not uploaded anywhere' }];
  return {
    module: 'image', input: name.slice(0, 120), generatedAt: now,
    result: { name: name.slice(0, 120), type, bytes: file.length, sha256: createHash('sha256').update(file).digest('hex'), verdict, risk, c2pa, generator, camera, software, metadata, reasons: reasons.sort((a, b) => b[1] - a[1]).map(([r]) => r), notes, advice },
    signals: [], provenance: prov,
  };
}
