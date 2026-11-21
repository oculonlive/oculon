import type { Provenance, Sourced } from './types.js';

/** Read an optional API key from the environment. */
export function key(name: string): string | undefined {
  const v = process.env[name]?.trim();
  return v ? v : undefined;
}

/** Provenance for a source that is skipped because its key is not configured. */
export function noKey<T>(source: string, envName: string): Sourced<T> {
  return { data: null, prov: missingKey(source, envName) };
}

export function missingKey(source: string, envName: string): Provenance {
  return { source, url: '', status: 'UNAVAILABLE', fetchedAt: new Date().toISOString(), note: `set ${envName} to enable` };
}

/** Remove known secret values from text before it is shown or stored. */
export function scrubSecrets(text: string): string {
  let out = text;
  for (const [k, v] of Object.entries(process.env)) {
    if (!v || v.length < 12 || !/KEY|TOKEN|SECRET|PASSWORD/.test(k)) continue;
    out = out.split(v).join('***');
  }
  return out;
}
