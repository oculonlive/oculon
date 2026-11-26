/**
 * Links Oculon is asked to open itself (page checks, archiving) must point at the public internet:
 * http or https, a real host name, no IP literals, no internal names, no odd ports.
 */
export function publicUrl(input: string): URL {
  let s = input.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
  let u: URL;
  try { u = new URL(s); } catch { throw new Error('not a valid link'); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('only http and https links are opened');
  const h = u.hostname.toLowerCase();
  if (!h.includes('.') || /^(\d+\.){3}\d+$|^\[|^0x|^localhost$|\.(local|internal|localhost|lan|home|corp|arpa)$/.test(h)) throw new Error('only links to public hosts are opened');
  if (u.port && !['80', '443', '8080', '8443'].includes(u.port)) throw new Error('only standard web ports are opened');
  u.username = ''; u.password = '';
  return u;
}
