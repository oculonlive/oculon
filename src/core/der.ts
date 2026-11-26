/** Organization and common names found in DER certificates (OIDs 2.5.4.10 and 2.5.4.3), without parsing ASN.1 fully. */
export function certNames(buf: Buffer, skip: RegExp = /timestamp|time ?stamping|\broot\b|intermediate|trusted g4|assured id|^ca$/i): string[] {
  const out = new Set<string>();
  for (const oid of [Buffer.from([0x06, 0x03, 0x55, 0x04, 0x0a]), Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03])]) {
    let at = buf.indexOf(oid);
    while (at >= 0 && out.size < 12) {
      const tag = buf[at + 5]!, len = buf[at + 6]!;
      if ([0x0c, 0x13, 0x14, 0x16].includes(tag) && len > 1 && len < 80) {
        const s = buf.toString('utf8', at + 7, at + 7 + len).trim();
        if (/^[\x20-\x7e]+$/.test(s) && !skip.test(s)) out.add(s);
      }
      at = buf.indexOf(oid, at + 1);
    }
  }
  return [...out];
}
