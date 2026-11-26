/**
 * Signature decoder: paste what a wallet asks you to sign and read what it really allows, before you sign it.
 * Understands:
 *   - EIP-712 typed data (eth_signTypedData_v4): ERC-2612 and DAI permits, Uniswap Permit2 (allowance and
 *     signature transfers), Seaport orders (what you give and what you get back), and any other typed message.
 *   - Transaction calldata, alone or as a { to, data, value } object: approve, increaseAllowance,
 *     setApprovalForAll, transfer, transferFrom, NFT transfers, Permit2 approve, and multicall bundles of these.
 *     Unknown functions are named through the public signature databases.
 *   - Raw 32-byte hashes (eth_sign), which hide what they authorize.
 * The spender or receiver is looked up on chain (wallet or contract, verified or not) when an address is known.
 * Decoding is local; only the address and selector lookups go out.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { codeAt, EVM_CHAINS, evmChain, formatUnits, isAddr, labelOf, sourcify, tokenMeta, UNLIMITED, wordAddr, wordInt, type EvmChain } from '../sources/evm.js';
import { decodeSelectors } from '../sources/signatures.js';

export interface SignatureReport {
  kind: 'typed data' | 'transaction' | 'raw hash' | 'message';
  type: string;
  verdict: 'dangerous signature' | 'risky signature' | 'check before signing' | 'no known risk found';
  risk: number;
  summary: string;
  allows: string[];
  reasons: string[];
  parties: { address: string; role: string; name: string | null; type: string | null }[];
  chain: string | null;
  advice: string[];
}

type Any = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const big = (v: unknown): bigint | null => { try { return v === undefined || v === null || v === '' ? null : BigInt(String(v)); } catch { return null; } };
const isUnl = (v: bigint | null) => v !== null && v >= UNLIMITED;
const when = (s: unknown) => { const n = Number(s); return !n ? null : n > 1e12 ? new Date(n).toISOString().slice(0, 10) : new Date(n * 1000).toISOString().slice(0, 10); };
const farFuture = (s: unknown) => { const n = Number(s); return !n || n > Date.now() / 1000 + 365 * 86_400 * 5; };

interface Ctx2 { ctx: Ctx; chain: EvmChain | null; parties: SignatureReport['parties']; reasons: [string, number][]; allows: string[]; prov: Provenance[] }

async function party(x: Ctx2, address: string, role: string) {
  const a = String(address).toLowerCase();
  if (!isAddr(a) || x.parties.some((p) => p.address === a && p.role === role)) return;
  const name = labelOf(a);
  let type: string | null = name ? 'known' : null;
  if (!name && x.chain) {
    const code = await codeAt(x.ctx, x.chain, a);
    if (code === '0x' || (code && /^0xef0100/i.test(code))) type = 'wallet';
    else if (code) type = (await sourcify(x.ctx, x.chain, a)).data ? 'verified contract' : 'unverified contract';
  }
  x.parties.push({ address: a, role, name, type });
  if (/spender|operator|receiver of your assets/.test(role)) {
    if (type === 'wallet') x.reasons.push([`the ${role} is a plain wallet, not an app contract: this is how drainers collect approvals`, 45]);
    if (type === 'unverified contract') x.reasons.push([`the ${role} is a contract with unpublished code`, 25]);
  }
}

async function tokenLabel(x: Ctx2, token: string): Promise<{ sym: string; dec: number | null }> {
  if (!x.chain || !isAddr(token)) return { sym: String(token).slice(0, 12), dec: null };
  const m = await tokenMeta(x.ctx, x.chain, token);
  return { sym: m.symbol ?? token.slice(0, 10), dec: m.decimals };
}

async function typed(x: Ctx2, d: Any): Promise<string> {
  const pt = String(d.primaryType ?? '');
  const m = (d.message ?? {}) as Any;
  const dom = (d.domain ?? {}) as Any;
  const vc = String(dom.verifyingContract ?? '').toLowerCase();
  if (dom.chainId && !x.chain) { const id = Number(dom.chainId); const k = Object.values(EVM_CHAINS).find((c) => c.id === id); if (k) x.chain = k; }
  if (pt === 'Permit' && m.spender) {
    const t = await tokenLabel(x, vc);
    const allowed = m.allowed !== undefined ? Boolean(m.allowed) : null;
    const v = allowed === null ? big(m.value) : allowed ? 1n << 255n : 0n;
    const amt = isUnl(v) ? `all your ${t.sym}` : `${formatUnits(v ?? 0n, t.dec)} ${t.sym}`;
    x.allows.push(`${m.spender} can take ${amt} from your wallet${m.deadline || m.expiry ? `, until ${when(m.deadline ?? m.expiry) ?? 'forever'}` : ''}, with no further transaction from you`);
    if (isUnl(v)) x.reasons.push(['unlimited permit: the spender can take every token of this kind, now and later', 35]);
    if (farFuture(m.deadline ?? m.expiry)) x.reasons.push(['the permit never expires (or not for years)', 10]);
    x.reasons.push(['permits move no tokens when signed, so wallets often show them as harmless; they are the most common drain signature', 15]);
    await party(x, m.spender, 'spender');
    return `Token permit (${t.sym})`;
  }
  if ((pt === 'PermitSingle' || pt === 'PermitBatch') && m.spender) {
    const det = (Array.isArray(m.details) ? m.details : [m.details]).filter(Boolean) as Any[];
    for (const dd of det) {
      const t = await tokenLabel(x, String(dd.token));
      const v = big(dd.amount);
      x.allows.push(`${m.spender} can take ${isUnl(v) ? `all your ${t.sym}` : `${formatUnits(v ?? 0n, t.dec)} ${t.sym}`} through Permit2, until ${when(dd.expiration) ?? 'forever'}`);
      if (isUnl(v)) x.reasons.push([`unlimited Permit2 allowance for ${t.sym}`, 30]);
    }
    if (det.length > 1) x.reasons.push([`${det.length} tokens in one signature: drainers bundle every token they found in the wallet`, 25]);
    await party(x, m.spender, 'spender');
    return `Permit2 allowance (${det.length} token${det.length > 1 ? 's' : ''})`;
  }
  if (/^Permit(Batch)?(Witness)?TransferFrom$/.test(pt) && m.spender) {
    const perm = (Array.isArray(m.permitted) ? m.permitted : [m.permitted]).filter(Boolean) as Any[];
    for (const p of perm) {
      const t = await tokenLabel(x, String(p.token));
      x.allows.push(`${m.spender} can transfer ${formatUnits(big(p.amount) ?? 0n, t.dec)} ${t.sym} out of your wallet once, before ${when(m.deadline) ?? 'the deadline'}`);
    }
    if (perm.length > 2) x.reasons.push([`${perm.length} tokens moved in one signature`, 25]);
    await party(x, m.spender, 'spender');
    return 'Permit2 signature transfer';
  }
  if (pt === 'OrderComponents' || (m.offer && m.consideration)) {
    const offer = (m.offer ?? []) as Any[], cons = (m.consideration ?? []) as Any[];
    const offerer = String(m.offerer ?? '').toLowerCase();
    const toYou = cons.filter((c) => String(c.recipient ?? '').toLowerCase() === offerer);
    const desc = (i: Any) => `${[0].includes(Number(i.itemType)) ? 'native coin' : [1].includes(Number(i.itemType)) ? 'tokens' : 'NFT'} ${i.token ? String(i.token).slice(0, 10) : ''}${i.identifierOrCriteria && Number(i.itemType) >= 2 ? ` #${String(i.identifierOrCriteria).slice(0, 12)}` : ''} x${i.startAmount ?? i.endAmount ?? '?'}`;
    for (const o of offer) x.allows.push(`you give: ${desc(o)}`);
    for (const c of cons) x.allows.push(`${String(c.recipient ?? '').toLowerCase() === offerer ? 'you get' : `${String(c.recipient).slice(0, 10)}... gets`}: ${desc(c)}`);
    const youGet = toYou.reduce((s, c) => s + (big(c.startAmount) ?? 0n), 0n);
    if (offer.length && (!toYou.length || youGet === 0n)) x.reasons.push(['you give assets and get nothing back: this listing hands them over for free', 70]);
    if (offer.length >= 3) x.reasons.push([`${offer.length} items offered in one order`, 15]);
    for (const c of cons.filter((c) => String(c.recipient ?? '').toLowerCase() !== offerer).slice(0, 3)) await party(x, String(c.recipient), 'receiver of your assets');
    return 'Marketplace order (Seaport)';
  }
  // Any other typed message: list the addresses and amounts it names.
  const addrs = JSON.stringify(m).match(/0x[0-9a-fA-F]{40}/g) ?? [];
  for (const a of [...new Set(addrs)].slice(0, 4)) await party(x, a, 'named in the message');
  x.allows.push(`a "${pt || 'typed'}" message for ${dom.name ?? 'an app'}${vc ? ` (contract ${vc})` : ''}`);
  if (/order|permit|approv|transfer|withdraw|delegat/i.test(pt)) x.reasons.push([`"${pt}" messages can move or allow assets; only sign it on the app's real site`, 20]);
  return `Typed message (${pt || 'unknown'})`;
}

const SELECTORS: Record<string, string> = {
  '0x095ea7b3': 'approve', '0x39509351': 'increaseAllowance', '0xa22cb465': 'setApprovalForAll', '0xa9059cbb': 'transfer', '0x23b872dd': 'transferFrom',
  '0x42842e0e': 'safeTransferFrom', '0xb88d4fde': 'safeTransferFrom', '0xf242432a': 'safeTransferFrom (1155)', '0x2eb2c2d6': 'safeBatchTransferFrom', '0x87517c45': 'Permit2 approve',
  '0xac9650d8': 'multicall', '0x5ae401dc': 'multicall', '0xd505accf': 'permit',
};

async function calldata(x: Ctx2, data: string, to: string | null, value: bigint, depth = 0): Promise<string> {
  const sel = data.slice(0, 10).toLowerCase();
  const args = data.slice(10);
  const name = SELECTORS[sel];
  const t = to ? await tokenLabel(x, to) : { sym: 'the token', dec: null };
  if (sel === '0x095ea7b3' || sel === '0x39509351') {
    const spender = wordAddr(args, 0), v = wordInt(args, 1);
    if (v === 0n) { x.allows.push(`removes the approval of ${spender} for ${t.sym}`); return 'Revoke approval'; }
    x.allows.push(`${spender} can take ${isUnl(v) ? `all your ${t.sym}, now and later` : `${formatUnits(v, t.dec)} ${t.sym}`}`);
    if (isUnl(v)) x.reasons.push(['unlimited approval', 20]);
    await party(x, spender, 'spender');
    return `${name} (${t.sym})`;
  }
  if (sel === '0xa22cb465') {
    const op = wordAddr(args, 0), on = wordInt(args, 1) !== 0n;
    if (!on) { x.allows.push(`removes ${op} as operator`); return 'Revoke NFT approval'; }
    x.allows.push(`${op} can move every NFT you hold in collection ${to ?? ''}, now and later`);
    x.reasons.push(['approval for all NFTs in a collection: the most common NFT drain', 35]);
    await party(x, op, 'operator');
    return 'Approve all NFTs';
  }
  if (sel === '0xa9059cbb') {
    const rcp = wordAddr(args, 0), v = wordInt(args, 1);
    x.allows.push(`sends ${formatUnits(v, t.dec)} ${t.sym} to ${rcp}`);
    await party(x, rcp, 'recipient');
    return `Token transfer (${t.sym})`;
  }
  if (['0x23b872dd', '0x42842e0e', '0xb88d4fde', '0xf242432a'].includes(sel)) {
    const from = wordAddr(args, 0), rcp = wordAddr(args, 1);
    x.allows.push(`moves ${sel === '0x23b872dd' ? `${formatUnits(wordInt(args, 2), t.dec)} ${t.sym}` : `item #${wordInt(args, 2).toString().slice(0, 16)}`} from ${from} to ${rcp}`);
    await party(x, rcp, 'recipient');
    return name!;
  }
  if (sel === '0x2eb2c2d6') { x.allows.push(`moves a batch of items to ${wordAddr(args, 1)}`); x.reasons.push(['batch transfer of many items', 20]); await party(x, wordAddr(args, 1), 'recipient'); return name!; }
  if (sel === '0x87517c45') {
    const tok = wordAddr(args, 0), spender = wordAddr(args, 1), v = wordInt(args, 2);
    const tl = await tokenLabel(x, tok);
    x.allows.push(`${spender} can take ${isUnl(v) ? `all your ${tl.sym}` : `${formatUnits(v, tl.dec)} ${tl.sym}`} through Permit2 until ${when(wordInt(args, 3).toString()) ?? 'forever'}`);
    await party(x, spender, 'spender');
    return 'Permit2 approve';
  }
  if ((sel === '0xac9650d8' || sel === '0x5ae401dc') && depth === 0) {
    const base = sel === '0x5ae401dc' ? 1 : 0;
    const off = Number(wordInt(args, base)) / 32;
    const n = Number(wordInt(args, off));
    const inner: string[] = [];
    for (let i = 0; i < Math.min(n, 12); i++) {
      const o = off + 1 + Number(wordInt(args, off + 1 + i)) / 32;
      const len = Number(wordInt(args, o));
      const hex = args.slice((o + 1) * 64, (o + 1) * 64 + len * 2);
      if (hex.length >= 8) inner.push(await calldata(x, `0x${hex}`, to, 0n, 1));
    }
    return `Bundle of ${n} calls: ${inner.join(', ')}`;
  }
  // Unknown function: name it if a database knows it.
  const d = await decodeSelectors(x.ctx, [sel]).catch(() => ({}) as Record<string, string | null>);
  const sig = d[sel] ?? null;
  x.allows.push(`calls ${sig ?? `an unknown function ${sel}`} on ${to ?? 'a contract'}${value ? ` and sends ${formatUnits(value, 18)} ${x.chain?.native ?? 'ETH'}` : ''}`);
  if (!sig) x.reasons.push(['the function is not in any public signature database: nobody can say what it does', 20]);
  if (value && sig && /^(claim|claimreward|claimrewards|claimairdrop|securityupdate|connect|verify|airdrop|mint)\b/i.test(sig) && !sig.includes(',')) x.reasons.push([`"${sig.split('(')[0]}" with a payment attached: a classic fake airdrop or "security update" drainer`, 40]);
  if (to) await party(x, to, 'contract called');
  return sig ? `Call ${sig.split('(')[0]}` : 'Unknown call';
}

export async function signatureCheck(ctx: Ctx, input: string, opts: { chain?: string; to?: string } = {}): Promise<ModuleResult<SignatureReport>> {
  const raw = input.trim();
  if (!raw) throw new Error('paste the signature request: typed data JSON, transaction data (0x...), or the message');
  if (raw.length > 100_000) throw new Error('the request is too long (max 100,000 characters)');
  const x: Ctx2 = { ctx, chain: opts.chain ? evmChain(opts.chain) : null, parties: [], reasons: [], allows: [], prov: [] };
  let kind: SignatureReport['kind'] = 'message', type = 'Plain message';
  let parsed: Any | null = null;
  try { parsed = JSON.parse(raw) as Any; } catch {}
  if (parsed && Array.isArray(parsed.params)) parsed = (parsed.params.find((p: unknown) => typeof p === 'object' || (typeof p === 'string' && p.trim().startsWith('{'))) as Any) ?? parsed;
  if (typeof parsed === 'string') { try { parsed = JSON.parse(parsed) as Any; } catch {} }

  if (parsed && typeof parsed === 'object' && (parsed.primaryType || parsed.types)) {
    kind = 'typed data';
    type = await typed(x, parsed);
  } else if (parsed && typeof parsed === 'object' && typeof parsed.data === 'string') {
    kind = 'transaction';
    if (!x.chain && parsed.chainId) { const id = Number(parsed.chainId); x.chain = Object.values(EVM_CHAINS).find((c) => c.id === id) ?? null; }
    if (!x.chain) x.chain = evmChain('eth');
    const v = big(parsed.value) ?? 0n;
    type = parsed.data.length >= 10 ? await calldata(x, parsed.data, parsed.to ? String(parsed.to).toLowerCase() : null, v) : 'Plain transfer';
    if (parsed.data.length < 10 && parsed.to) { x.allows.push(`sends ${formatUnits(v, 18)} ${x.chain.native} to ${parsed.to}`); await party(x, parsed.to, 'recipient'); }
  } else if (/^0x[0-9a-fA-F]{64}$/.test(raw)) {
    kind = 'raw hash';
    type = 'Raw hash (eth_sign)';
    x.allows.push('nothing you can read: a raw hash can stand for any transaction, including one that empties the wallet');
    x.reasons.push(['blind signature: a raw 32-byte hash hides what it authorizes. Legitimate apps do not ask for this', 75]);
  } else if (/^0x[0-9a-fA-F]{8,}$/.test(raw)) {
    kind = 'transaction';
    x.chain ??= evmChain('eth');
    type = await calldata(x, raw, opts.to && isAddr(opts.to) ? opts.to.toLowerCase() : null, 0n);
  } else {
    let text = raw;
    if (/^0x[0-9a-fA-F]+$/.test(raw)) { try { text = Buffer.from(raw.slice(2), 'hex').toString('utf8'); } catch {} }
    x.allows.push(`signs the text: "${text.slice(0, 160)}${text.length > 160 ? '...' : ''}"`);
    if (/seed|recovery phrase|private key|mnemonic/i.test(text)) x.reasons.push(['the message mentions your seed phrase or private key: no real app asks for that', 80]);
    if (/sign.?in|login|log in|nonce|verify (your )?wallet|SIWE|wants you to sign in/i.test(text)) {
      type = 'Sign-in message';
      const dom = /^(\S+) wants you to sign in/m.exec(text)?.[1];
      if (dom) x.allows.push(`proves you own this wallet to ${dom}. Check that ${dom} is the site you are on`);
    }
  }

  const reasons = x.reasons.sort((a, b) => b[1] - a[1]);
  const risk = Math.min(100, reasons.reduce((s, [, w]) => s + w, 0));
  const verdict: SignatureReport['verdict'] = risk >= 70 ? 'dangerous signature' : risk >= 40 ? 'risky signature' : risk >= 15 || kind === 'typed data' ? 'check before signing' : 'no known risk found';
  const summary = x.allows[0] ?? type;
  const advice = verdict === 'dangerous signature'
    ? ['Do not sign. Close the site.', 'If you already signed, revoke approvals right away (oculon approvals <wallet>) and move your funds to a new wallet.']
    : verdict === 'risky signature'
      ? ['Only sign if you started this yourself on the real site of the app, and the spender is the app you expect.', 'Prefer a limited amount over unlimited.']
      : ['Sign only on the site you meant to use. Typed messages and approvals can move assets later without another prompt.'];
  return {
    module: 'signature', input: raw.slice(0, 200), generatedAt: ctx.now().toISOString(),
    result: { kind, type, verdict, risk, summary, allows: x.allows.slice(0, 20), reasons: reasons.map(([r]) => r), parties: x.parties, chain: x.chain?.label ?? null, advice },
    signals: [], provenance: [{ source: 'oculon-signature', url: 'local', status: 'LIVE', fetchedAt: ctx.now().toISOString(), note: 'decoded locally; addresses and selectors looked up on chain' }, ...x.prov],
  };
}

