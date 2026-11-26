/**
 * Android app check: is this APK safe to install? Built for the fake apps sent in chats ("invoice", "parcel",
 * "wedding invitation", "photo") that steal one-time codes and take over banking apps.
 *   Manifest: package name, version, SDK levels and every permission, read from the binary AndroidManifest.xml
 *     (parsed here). Services that ask for accessibility, notification access or device admin, and receivers
 *     that wake on incoming SMS, are what banking trojans use.
 *   Signer: organization and name in the signing certificate; the Android debug key means it was never
 *     published through a store.
 *   Malware: the file's SHA-256 looked up in malware databases (the hash check).
 * The file is read, never installed or run.
 */
import { createHash } from 'node:crypto';
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { signalId } from '../core/text.js';
import { certNames } from '../core/der.js';
import { zipEntries, zipRead } from '../core/zip.js';
import { hashCheck } from './hashcheck.js';

export const APK_MAX_BYTES = 40 * 1024 * 1024;

export interface ApkReport {
  name: string;
  bytes: number;
  sha256: string;
  package: string | null;
  version: string | null;
  minSdk: number | null;
  targetSdk: number | null;
  verdict: 'known malware' | 'dangerous app' | 'risky permissions' | 'no known risk found';
  risk: number;
  permissions: string[];
  risky: { permission: string; why: string }[];
  services: string[];
  signer: string[];
  debugSigned: boolean;
  malware: { verdict: string; name: string | null; family: string | null } | null;
  reasons: string[];
  advice: string[];
}

interface Node { name: string; attrs: Record<string, string> }

/** Elements of a binary Android XML file, with attribute values as text. */
export function parseAxml(b: Buffer): Node[] {
  const nodes: Node[] = [];
  if (b.length < 8 || b.readUInt16LE(0) !== 0x0003) throw new Error('not a binary Android XML file');
  let strings: string[] = [];
  let resIds: number[] = [];
  const ANDROID_ATTR: Record<number, string> = { 0x01010003: 'name', 0x0101021b: 'versionCode', 0x0101021c: 'versionName', 0x0101020c: 'minSdkVersion', 0x01010270: 'targetSdkVersion', 0x01010006: 'permission', 0x01010001: 'label' };
  let p = b.readUInt16LE(2);
  while (p + 8 <= b.length) {
    const type = b.readUInt16LE(p), hsz = b.readUInt16LE(p + 2), size = b.readUInt32LE(p + 4);
    if (size < 8 || p + size > b.length) break;
    if (type === 0x0001) {
      const n = b.readUInt32LE(p + 8), flags = b.readUInt32LE(p + 16), start = b.readUInt32LE(p + 20);
      const utf8 = (flags & 0x100) !== 0;
      strings = [];
      for (let i = 0; i < n; i++) {
        let o = p + start + b.readUInt32LE(p + hsz + i * 4);
        try {
          if (utf8) {
            if (b[o]! & 0x80) o += 2; else o += 1;
            let len = b[o]!; o += 1;
            if (len & 0x80) { len = ((len & 0x7f) << 8) | b[o]!; o += 1; }
            strings.push(b.toString('utf8', o, o + len));
          } else {
            let len = b.readUInt16LE(o); o += 2;
            if (len & 0x8000) { len = ((len & 0x7fff) << 16) | b.readUInt16LE(o); o += 2; }
            strings.push(b.toString('utf16le', o, o + len * 2));
          }
        } catch { strings.push(''); }
      }
    } else if (type === 0x0180) {
      resIds = [];
      for (let o = p + 8; o + 4 <= p + size; o += 4) resIds.push(b.readUInt32LE(o));
    } else if (type === 0x0102) {
      const nameIdx = b.readUInt32LE(p + 20);
      const attrStart = b.readUInt16LE(p + 24), attrSize = b.readUInt16LE(p + 26), count = b.readUInt16LE(p + 28);
      const attrs: Record<string, string> = {};
      for (let i = 0; i < count; i++) {
        const a = p + 16 + attrStart + i * attrSize;
        const ni = b.readUInt32LE(a + 4), raw = b.readUInt32LE(a + 8), dt = b[a + 15]!, data = b.readUInt32LE(a + 16);
        // Obfuscated apps blank attribute names; the resource id still says which android: attribute it is.
        const key = strings[ni] || ANDROID_ATTR[resIds[ni] ?? -1] || `attr${ni}`;
        attrs[key] = raw !== 0xffffffff ? strings[raw] ?? '' : dt === 0x03 ? strings[data] ?? '' : dt === 0x12 ? String(data !== 0) : dt === 0x01 ? `@0x${data.toString(16)}` : String(data);
      }
      nodes.push({ name: strings[nameIdx] ?? '', attrs });
    }
    p += size;
  }
  return nodes;
}

const PERMS: [RegExp, string, number][] = [
  [/\.(RECEIVE|READ)_SMS$/, 'reads incoming SMS: how one-time banking codes are stolen', 30],
  [/\.SEND_SMS$/, 'sends SMS from your number (premium texts, spreading itself)', 15],
  [/\.SYSTEM_ALERT_WINDOW$/, 'draws over other apps: fake login screens on top of your banking app', 15],
  [/\.REQUEST_INSTALL_PACKAGES$/, 'installs other apps: a first stage that downloads the real malware', 15],
  [/\.(READ_CALL_LOG|PROCESS_OUTGOING_CALLS|ANSWER_PHONE_CALLS|CALL_PHONE)$/, 'reads or controls phone calls', 10],
  [/\.READ_CONTACTS$/, 'reads your contacts (often used to send itself to them)', 5],
  [/\.QUERY_ALL_PACKAGES$/, 'lists every app you have installed (to find banking apps)', 5],
  [/\.(READ_PHONE_STATE|READ_PHONE_NUMBERS)$/, 'reads your phone number and SIM details', 5],
  [/\.(RECORD_AUDIO)$/, 'records audio', 5],
  [/\.(CAMERA)$/, 'uses the camera', 2],
  [/\.(ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION)$/, 'tracks location', 3],
];
const SERVICES: [RegExp, string, number][] = [
  [/BIND_ACCESSIBILITY_SERVICE/, 'asks for accessibility access: it can read the screen and tap for you, the core of banking trojans', 35],
  [/BIND_NOTIFICATION_LISTENER_SERVICE/, 'asks to read all notifications, including one-time codes', 20],
  [/BIND_DEVICE_ADMIN/, 'asks for device administrator rights, which makes it hard to uninstall', 25],
];
const LURE = /invoice|receipt|parcel|delivery|courier|tracking|wedding|invitation|photo|viewer|pdf|document|tax|refund|fine|ticket|update|security|bank|wallet|support/i;

export async function apkCheck(ctx: Ctx, file: Buffer, name = 'app.apk'): Promise<ModuleResult<ApkReport>> {
  if (!file.length) throw new Error('the file is empty');
  if (file.length > APK_MAX_BYTES) throw new Error('the app is larger than 40 MB');
  if (file.readUInt32LE(0) !== 0x04034b50) throw new Error('not an APK (Android apps are ZIP files)');
  const entries = zipEntries(file);
  const man = entries.find((e) => e.name === 'AndroidManifest.xml');
  if (!man) throw new Error('no AndroidManifest.xml: not an Android app');
  const nodes = parseAxml(zipRead(file, man) ?? Buffer.alloc(0));
  const provenance: Provenance[] = [{ source: 'oculon-apk', url: 'local', status: 'LIVE', fetchedAt: ctx.now().toISOString(), note: 'manifest and certificates read here; the app is not installed or run' }];
  const manifest = nodes.find((n) => n.name === 'manifest');
  const sdk = nodes.find((n) => n.name === 'uses-sdk');
  const permissions = [...new Set(nodes.filter((n) => /^uses-permission/.test(n.name)).map((n) => n.attrs.name ?? '').filter(Boolean))];
  const svcPerms = nodes.filter((n) => n.name === 'service' || n.name === 'receiver').map((n) => n.attrs.permission ?? '').filter(Boolean);
  const actions = nodes.filter((n) => n.name === 'action').map((n) => n.attrs.name ?? '');
  const reasons: [string, number][] = [];
  const risky: ApkReport['risky'] = [];
  for (const p of permissions) for (const [re, why, w] of PERMS) if (re.test(p)) { risky.push({ permission: p.split('.').pop()!, why }); reasons.push([why, w]); }
  const services: string[] = [];
  for (const sp of [...new Set(svcPerms)]) for (const [re, why, w] of SERVICES) if (re.test(sp)) { services.push(sp.split('.').pop()!); reasons.push([why, w]); }
  if (actions.some((a) => /SMS_RECEIVED|SMS_DELIVER/.test(a))) reasons.push(['wakes up on every incoming SMS', 15]);
  if (actions.some((a) => /BOOT_COMPLETED/.test(a)) && reasons.length) reasons.push(['starts itself when the phone boots', 5]);

  // Signer: v1 certificates in META-INF, or the v2/v3 signing block before the central directory.
  const certs = entries.filter((e) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name));
  let signer: string[] = [];
  for (const c of certs) { const d = zipRead(file, c); if (d) signer.push(...certNames(d, /^$/)); }
  if (!signer.length) { const sig = file.lastIndexOf('APK Sig Block 42'); if (sig > 0) signer = certNames(file.subarray(Math.max(0, sig - 200_000), sig + 16), /^$/); }
  signer = [...new Set(signer)].slice(0, 6);
  const debugSigned = signer.some((s) => /android debug/i.test(s));
  if (debugSigned) reasons.push(['signed with the Android debug key: never published through an app store', 25]);
  if (!signer.length) reasons.push(['no signing certificate found', 10]);

  const pkg = manifest?.attrs.package ?? null;
  const dangerous = reasons.reduce((s, [, w]) => s + w, 0) >= 40;
  if (dangerous && (LURE.test(pkg ?? '') || LURE.test(name))) reasons.push([`the name (${LURE.exec(pkg ?? '')?.[0] ?? LURE.exec(name)?.[0]}) is the kind used to lure people into installing it from a chat`, 10]);
  if (dangerous && file.length < 3 * 1024 * 1024) reasons.push([`very small for an app that asks for this much (${(file.length / 1024 / 1024).toFixed(1)} MB)`, 5]);

  // Malware databases.
  const sha256 = createHash('sha256').update(file).digest('hex');
  let malware: ApkReport['malware'] = null;
  try {
    const h = await hashCheck(ctx, sha256);
    provenance.push(...h.provenance.slice(0, 4));
    malware = { verdict: h.result.verdict, name: h.result.name, family: h.result.family };
    if (h.result.verdict === 'malicious') reasons.unshift([`known malware${h.result.family ? ` (${h.result.family})` : ''} in malware databases`, 100]);
  } catch {}

  const risk = Math.min(100, reasons.reduce((s, [, w]) => s + w, 0));
  const verdict: ApkReport['verdict'] = malware?.verdict === 'malicious' ? 'known malware' : risk >= 60 ? 'dangerous app' : risk >= 25 ? 'risky permissions' : 'no known risk found';
  const advice = verdict === 'known malware' || verdict === 'dangerous app'
    ? ['Do not install it. Apps sent in a chat are the most common way phones get banking malware.', 'If it is already installed: turn on airplane mode, remove it in Settings > Apps (remove its admin and accessibility rights first), then call your bank from a number you know.']
    : verdict === 'risky permissions' ? ['Install apps only from Google Play or the maker\'s own site. Check that the permissions fit what the app does.'] : ['Nothing alarming in the manifest. Still prefer the store version of any app.'];
  const now = ctx.now().toISOString();
  const signals: Signal[] = verdict === 'known malware' || risk >= 80 ? [{ id: signalId('apk', sha256), module: 'apk', title: `Android app ${pkg ?? name}: ${verdict}`, score: Math.max(risk, 70), entity: `apk:${sha256.slice(0, 16)}`, evidence: reasons.slice(0, 3).map(([t]) => ({ source: 'oculon-apk', text: t })), createdAt: now }] : [];
  return {
    module: 'apk', input: name.slice(0, 120), generatedAt: now, signals, provenance,
    result: { name: name.slice(0, 120), bytes: file.length, sha256, package: pkg, version: manifest?.attrs.versionName ?? null, minSdk: sdk?.attrs.minSdkVersion ? Number(sdk.attrs.minSdkVersion) || null : null, targetSdk: sdk?.attrs.targetSdkVersion ? Number(sdk.attrs.targetSdkVersion) || null : null, verdict, risk, permissions, risky, services, signer, debugSigned, malware, reasons: reasons.sort((a, b) => b[1] - a[1]).map(([r]) => r), advice },
  };
}
