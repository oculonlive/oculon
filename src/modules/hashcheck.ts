/**
 * File hash check: is this file known malware, a known good file, or unknown?
 * MD5, SHA-1 or SHA-256, checked against CIRCL hashlookup (NIST NSRL and other known-software sets),
 * MalwareBazaar and ThreatFox (abuse.ch), AlienVault OTX threat reports and VirusTotal engine verdicts.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { circlHash, malwareBazaar, otx, threatFox, virusTotal, type BazaarHit, type CirclHit, type OtxPulses, type ThreatFoxHit, type VtStats } from '../sources/threatintel.js';

export type HashVerdict = 'malicious' | 'suspicious' | 'known good' | 'unknown';

export interface HashCheck {
  hash: string;
  algorithm: 'md5' | 'sha1' | 'sha256';
  verdict: HashVerdict;
  reasons: string[];
  name: string | null;
  family: string | null;
  circl: CirclHit | null;
  bazaar: BazaarHit | null;
  threatfox: ThreatFoxHit[];
  otx: OtxPulses | null;
  virustotal: VtStats | null;
  advice: string[];
}

export function hashAlgorithm(h: string): HashCheck['algorithm'] | null {
  if (/^[a-f0-9]{32}$/i.test(h)) return 'md5';
  if (/^[a-f0-9]{40}$/i.test(h)) return 'sha1';
  if (/^[a-f0-9]{64}$/i.test(h)) return 'sha256';
  return null;
}

export function judgeHash(x: Pick<HashCheck, 'circl' | 'bazaar' | 'threatfox' | 'otx' | 'virustotal'>): { verdict: HashVerdict; reasons: string[] } {
  const reasons: string[] = [];
  const v = x.virustotal;
  let bad = false;
  let warn = false;
  if (x.bazaar) { bad = true; reasons.push(`a MalwareBazaar sample${x.bazaar.signature ? ` of ${x.bazaar.signature}` : ''}, first seen ${x.bazaar.firstSeen?.slice(0, 10) ?? 'earlier'}`); }
  if (x.threatfox.length) { bad = true; reasons.push(`ThreatFox lists it as an indicator${x.threatfox[0]!.malware ? ` of ${x.threatfox[0]!.malware}` : ''}`); }
  if (x.circl?.knownMalicious) { bad = true; reasons.push(`CIRCL marks it as known malicious (${x.circl.knownMalicious})`); }
  if (v) {
    if (v.malicious >= 5) { bad = true; reasons.push(`${v.malicious} of ${v.engines} VirusTotal engines detect it${v.label ? ` as ${v.label}` : ''}`); }
    else if (v.malicious > 0) { warn = true; reasons.push(`${v.malicious} of ${v.engines} VirusTotal engines detect it; a few detections are often false positives`); }
    else if (v.engines) reasons.push(`no detections from ${v.engines} VirusTotal engines`);
  }
  if (x.otx && x.otx.count > 0) { warn = true; reasons.push(`mentioned in ${x.otx.count} AlienVault OTX threat report${x.otx.count === 1 ? '' : 's'}`); }
  if (x.circl?.known && !x.circl.knownMalicious) reasons.push(`a known file in ${x.circl.sources.join(', ') || 'the CIRCL known-file sets'}${x.circl.fileName ? ` (${x.circl.fileName})` : ''}`);
  const verdict: HashVerdict = bad ? 'malicious' : warn ? 'suspicious' : x.circl?.known ? 'known good' : 'unknown';
  if (verdict === 'unknown' && !reasons.length) reasons.push('no source has seen this hash');
  return { verdict, reasons };
}

export async function hashCheck(ctx: Ctx, input: string): Promise<ModuleResult<HashCheck>> {
  const hash = input.trim().toLowerCase();
  const algorithm = hashAlgorithm(hash);
  if (!algorithm) throw new Error(`not a file hash: give an MD5 (32), SHA-1 (40) or SHA-256 (64) hex hash`);
  const [circl, mb, tf, ox, vt] = await Promise.all([
    circlHash(ctx, algorithm, hash),
    malwareBazaar(ctx, hash),
    algorithm === 'sha1' ? Promise.resolve({ data: [] as ThreatFoxHit[], prov: null as Provenance | null }) : threatFox(ctx, 'hash', hash),
    otx(ctx, 'file', hash),
    virusTotal(ctx, 'file', hash),
  ]);
  const provenance = [circl.prov, mb.prov, ...(tf.prov ? [tf.prov] : []), ox.prov, vt.prov];
  const part = { circl: circl.data, bazaar: mb.data, threatfox: tf.data ?? [], otx: ox.data, virustotal: vt.data };
  const { verdict, reasons } = judgeHash(part);
  const family = mb.data?.signature ?? tf.data?.[0]?.malware ?? vt.data?.label ?? ox.data?.family[0] ?? null;
  const advice = verdict === 'malicious'
    ? ['Do not open or run this file. Delete it, and if it already ran, disconnect the device and scan it.', 'Look for the same hash on other machines in your network.']
    : verdict === 'suspicious'
      ? ['Do not run it yet. Upload it to a sandbox or wait for more engines to agree before trusting it.']
      : verdict === 'known good'
        ? ['This matches a known software file. Make sure it came from the vendor it claims to be from.']
        : ['Nobody has reported this file. That is common for new or private files, and is not proof it is safe.'];
  return {
    module: 'hashcheck',
    input: hash,
    generatedAt: ctx.now().toISOString(),
    result: { hash, algorithm, verdict, reasons, name: mb.data?.fileName ?? vt.data?.name ?? circl.data?.fileName ?? null, family, ...part, advice },
    signals: [],
    provenance,
  };
}
