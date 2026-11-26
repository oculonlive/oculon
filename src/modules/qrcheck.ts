/**
 * QR code check (quishing): read the QR code in a photo or screenshot, then check what it points to.
 * The code is read here, without an upload (see core/qr.ts). Then:
 *   - a link goes through the URL check (Safe Browsing, URLhaus, urlscan.io, domain age, lookalikes),
 *   - a crypto payment code (ethereum:, bitcoin:, solana:) or a bare address goes through the address check,
 *   - an EPC / SEPA payment code has its IBAN checked,
 *   - Wi-Fi, phone, SMS and email codes are shown as what they would do.
 * Fake parking-meter, parcel and "verify your account" QR codes are the common case.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { decodeGray } from '../core/raster.js';
import { readQr } from '../core/qr.js';
import { urlCheck } from './urlcheck.js';
import { addressCheck, detectChain } from './address.js';
import { checkIban } from './iban.js';

export interface QrReport {
  name: string;
  found: boolean;
  content: string | null;
  kind: 'link' | 'crypto payment' | 'bank payment' | 'wifi' | 'phone' | 'sms' | 'email' | 'contact' | 'text' | null;
  verdict: string;
  risk: number;
  target: Record<string, string>;
  reasons: string[];
  advice: string[];
  check: unknown;
}

export async function qrCheck(ctx: Ctx, file: Buffer, name = 'image'): Promise<ModuleResult<QrReport>> {
  if (!file.length) throw new Error('the file is empty');
  if (file.length > 15 * 1024 * 1024) throw new Error('the image is larger than 15 MB');
  const now = ctx.now().toISOString();
  const provenance: Provenance[] = [{ source: 'oculon-qr', url: 'local', status: 'LIVE', fetchedAt: now, note: 'QR code read from the image here, not uploaded' }];
  const texts = readQr(decodeGray(file));
  const base = { name: name.slice(0, 120), target: {} as Record<string, string>, reasons: [] as string[], check: null as unknown };
  if (!texts.length) {
    return { module: 'qr', input: base.name, generatedAt: now, signals: [], provenance, result: { ...base, found: false, content: null, kind: null, verdict: 'no QR code found', risk: 0, advice: ['Crop the photo to the code, keep it sharp and straight, or take a screenshot of it. Codes larger than version 15 (about 400 characters) are not read yet.'] } };
  }
  const content = texts[0]!.trim();
  const t = base.target, reasons = base.reasons;
  let kind: QrReport['kind'] = 'text', verdict = 'no known risk found', risk = 0, check: unknown = null;
  let advice: string[] = ['Only scan codes from a source you trust. A sticker on a parking meter or a letter you did not expect is the common trick.'];

  const crypto = /^(ethereum|bitcoin|solana|tron|litecoin):(?:pay-)?([^?@/\s]+)/i.exec(content);
  const bare = !crypto && !/\s/.test(content) && detectChain(content).chain !== 'unknown' ? content : null;
  if (/^https?:\/\//i.test(content) || /^www\./i.test(content)) {
    kind = 'link';
    t.url = content;
    const r = await urlCheck(ctx, content);
    provenance.push(...r.provenance);
    check = { verdict: r.result.verdict, risk: r.result.risk, domain: r.result.domain, reasons: r.result.reasons, domainAgeDays: r.result.domainInfo?.ageDays ?? null };
    verdict = r.result.verdict; risk = r.result.risk;
    reasons.push(...r.result.reasons.slice(0, 8));
    if (/^https?:\/\/[^/]*\b(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|qrco\.de|qr\.page)\b/i.test(content)) { reasons.push('a link shortener hides where the code really goes'); risk = Math.max(risk, 25); }
    advice = risk >= 50 ? ['Do not open the link and do not pay through it. Pay at the official app or website you type in yourself.'] : ['Check the domain in the browser bar after it opens, before you log in or pay.'];
  } else if (crypto || bare) {
    kind = 'crypto payment';
    const addr = crypto ? crypto[2]! : bare!;
    t.address = addr;
    if (crypto) {
      t.network = crypto[1]!.toLowerCase();
      const amt = /[?&](?:amount|value)=([^&]+)/i.exec(content)?.[1];
      if (amt) t.amount = decodeURIComponent(amt);
      const chainId = /@(\d+)/.exec(content)?.[1];
      if (chainId) t.chainId = chainId;
      if (/\/transfer\?address=/i.test(content)) { t.token = addr; t.address = /address=(0x[0-9a-fA-F]{40})/.exec(content)?.[1] ?? addr; }
    }
    try {
      const r = await addressCheck(ctx, t.address!);
      provenance.push(...r.provenance);
      check = r.result;
      reasons.push(...r.result.warnings);
      risk = r.result.sanctioned ? 90 : r.result.warnings.length ? 30 : 0;
      verdict = r.result.sanctioned ? 'sanctioned address' : r.result.warnings.length ? 'check the address' : 'no known risk found';
    } catch (e) { reasons.push(`address not checked: ${(e as Error).message}`); }
    advice = ['Compare the whole address with the one the recipient gave you through another channel before paying.'];
  } else if (/^BCD\r?\n/.test(content)) {
    kind = 'bank payment';
    const L = content.split(/\r?\n/);
    t.name = L[5] ?? ''; t.iban = L[6] ?? ''; if (L[7]) t.amount = L[7]; if (L[9] || L[10]) t.reference = (L[9] || L[10])!;
    const ib = checkIban(t.iban);
    check = ib;
    if (!ib.valid) { risk = 60; verdict = 'invalid IBAN'; reasons.push(`the IBAN in the code is not valid (${ib.problems[0] ?? 'checksum fails'})`); }
    else { verdict = 'check the recipient'; risk = 15; reasons.push(`pays ${t.amount ?? 'an amount you choose'} to ${t.name} (${ib.formatted ?? t.iban}${ib.countryName ? `, ${ib.countryName}` : ''})`); }
    advice = ['Check the recipient name your bank shows before you confirm the payment.'];
  } else if (/^WIFI:/i.test(content)) {
    kind = 'wifi';
    t.network = /S:((?:[^;\\]|\\.)*)/.exec(content)?.[1] ?? '';
    t.security = /T:([^;]*)/.exec(content)?.[1] || 'none';
    verdict = 'joins a Wi-Fi network'; risk = t.security === 'none' || /nopass/i.test(t.security) ? 20 : 5;
    reasons.push(`connects to Wi-Fi "${t.network}" (${t.security})`);
    advice = ['Only join networks you expect at this place; an open network can watch your traffic.'];
  } else if (/^tel:/i.test(content)) { kind = 'phone'; t.number = content.slice(4); verdict = 'calls a number'; reasons.push(`calls ${t.number}`); }
  else if (/^(smsto|sms):/i.test(content)) { kind = 'sms'; const [, num, body] = /^(?:smsto|sms):([^:?]*)[:?]?(?:body=)?(.*)$/i.exec(content) ?? []; t.number = num ?? ''; t.message = (body ?? '').slice(0, 200); verdict = 'sends a text message'; risk = 15; reasons.push(`prepares a text to ${t.number}: premium numbers cost money`); }
  else if (/^mailto:/i.test(content)) { kind = 'email'; t.to = content.slice(7).split('?')[0]!; verdict = 'writes an email'; reasons.push(`opens an email to ${t.to}`); }
  else if (/^BEGIN:VCARD/i.test(content) || /^MECARD:/i.test(content)) { kind = 'contact'; t.name = /(?:FN|N):([^\r\n;]+)/.exec(content)?.[1] ?? ''; verdict = 'adds a contact'; reasons.push(`adds contact ${t.name}`); }
  else {
    t.text = content.slice(0, 300);
    const m = /\b((?:[a-z0-9-]+\.)+[a-z]{2,})(\/\S*)?/i.exec(content);
    if (m) { reasons.push(`the text names ${m[1]}`); }
  }
  return { module: 'qr', input: base.name, generatedAt: now, signals: [], provenance, result: { name: base.name, found: true, content: content.slice(0, 2000), kind, verdict, risk, target: t, reasons, advice, check } };
}
