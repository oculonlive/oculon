/**
 * Approval check: who can move tokens out of this wallet right now.
 * Reads every ERC-20 Approval and NFT ApprovalForAll event the wallet ever signed (Etherscan logs), then asks the
 * chain what is still allowed today (allowance / isApprovedForAll through a public RPC), so revoked and used-up
 * approvals drop out. Each spender is named when it is a known router or marketplace; unknown spenders, plain
 * wallets (not contracts) and unverified contracts with unlimited access are flagged, since that is how drainers
 * keep access after a bad signature.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { signalId } from '../core/text.js';
import { alchemyIsSpam, codeAt, esLogs, esTxList, ethCall, evmChain, formatUnits, isAddr, labelOf, pad, sourcify, tokenMeta, TOPIC, topicAddr, UNLIMITED, wordInt } from '../sources/evm.js';
import { screen } from './sanctions.js';

export interface Approval {
  token: string;
  tokenName: string | null;
  symbol: string | null;
  kind: 'token' | 'nft';
  spender: string;
  spenderName: string | null;
  spenderType: 'known' | 'verified contract' | 'unverified contract' | 'wallet' | 'unknown';
  amount: string;
  unlimited: boolean;
  approvedAt: string | null;
  risk: 'high' | 'medium' | 'low';
  why: string | null;
}

export interface ApprovalsReport {
  address: string;
  chain: string;
  verdict: 'dangerous approvals' | 'risky approvals' | 'review approvals' | 'no risky approvals found' | 'no approvals found';
  risk: number;
  active: number;
  unlimited: number;
  checkedPairs: number;
  approvals: Approval[];
  reasons: string[];
  advice: string[];
  revokeUrl: string;
}

const MAX_PAIRS = 60;

export async function approvalsCheck(ctx: Ctx, input: string, opts: { chain?: string } = {}): Promise<ModuleResult<ApprovalsReport>> {
  const address = input.trim().toLowerCase();
  if (!isAddr(address)) throw new Error('give a wallet address: 0x followed by 40 hex characters');
  const c = evmChain(opts.chain, 'logs');
  const provenance: Provenance[] = [];
  const [erc, all, txs] = await Promise.all([esLogs(ctx, c, TOPIC.approval, `0x${pad(address)}`), esLogs(ctx, c, TOPIC.approvalForAll, `0x${pad(address)}`), esTxList(ctx, c, address, 1000)]);
  provenance.push(erc.prov, all.prov, txs.prov);
  // Spam tokens emit fake Approval events naming any wallet; only transactions the wallet sent are surely its own.
  const signed = new Set((txs.data ?? []).filter((t) => t.from.toLowerCase() === address).map((t) => t.hash.toLowerCase()));
  if (erc.data === null && all.data === null) throw new Error(`could not read approval history (${erc.prov.note ?? erc.prov.status})`);

  // Newest event per (token, spender). ERC-20 Approval has 3 topics; ERC-721 Approval (single NFT) has 4 and is skipped.
  const pairs = new Map<string, { token: string; spender: string; kind: 'token' | 'nft'; at: number; signed: boolean }>();
  for (const l of erc.data ?? []) {
    if (l.topics.length !== 3) continue;
    const k = `${l.address.toLowerCase()}|${topicAddr(l.topics[2]!)}|token`;
    const at = Number(l.timeStamp);
    if ((pairs.get(k)?.at ?? 0) <= at) pairs.set(k, { token: l.address.toLowerCase(), spender: topicAddr(l.topics[2]!), kind: 'token', at, signed: signed.has(l.transactionHash.toLowerCase()) });
  }
  for (const l of all.data ?? []) {
    if (l.topics.length < 3) continue;
    const k = `${l.address.toLowerCase()}|${topicAddr(l.topics[2]!)}|nft`;
    const at = Number(l.timeStamp);
    if ((pairs.get(k)?.at ?? 0) <= at) pairs.set(k, { token: l.address.toLowerCase(), spender: topicAddr(l.topics[2]!), kind: 'nft', at, signed: signed.has(l.transactionHash.toLowerCase()) });
  }
  // Approvals the wallet sent itself come first. Others (permits, or spam) count only when they point at an unknown
  // spender, since a permit to a drainer is exactly what this check is for; spam to well known routers is dropped.
  const ranked = [...pairs.values()].filter((p) => p.signed || !labelOf(p.spender)).sort((a, b) => Number(b.signed) - Number(a.signed) || b.at - a.at);
  const spam = pairs.size - ranked.length;
  const list = ranked.slice(0, MAX_PAIRS);

  // What is still allowed today.
  const live: { p: (typeof list)[number]; amount: bigint }[] = [];
  for (let i = 0; i < list.length; i += 10) {
    const chunk = list.slice(i, i + 10);
    const res = await Promise.all(chunk.map((p) => p.kind === 'token'
      ? ethCall(ctx, c, p.token, `0xdd62ed3e${pad(address)}${pad(p.spender)}`, 120)
      : ethCall(ctx, c, p.token, `0xe985e9c5${pad(address)}${pad(p.spender)}`, 120)));
    if (i === 0 && res[0]) provenance.push(res[0].prov);
    res.forEach((r, j) => { const v = r.data && r.data.length >= 66 ? wordInt(r.data, 0) : 0n; if (v > 0n) live.push({ p: chunk[j]!, amount: v }); });
  }
  // An approval the wallet did not send counts only on a token it holds and that supports permits; the rest is spam.
  for (let i = live.length - 1; i >= 0; i--) {
    const x = live[i]!;
    if (x.p.signed || x.p.kind === 'nft') continue;
    const b = await ethCall(ctx, c, x.p.token, `0x70a08231${pad(address)}`, 120);
    if (!b.data || b.data.length < 66 || wordInt(b.data, 0) === 0n) { live.splice(i, 1); continue; }
    // A real approval the wallet did not send comes from a signed permit, which needs a token that supports permits.
    const ds = await ethCall(ctx, c, x.p.token, '0x3644e515', 86_400);
    if (!ds.data || ds.data.length < 66 || /^0x0*$/.test(ds.data)) live.splice(i, 1);
  }

  // NFT approvals on collections Alchemy marks as spam are fake events, not something the wallet granted.
  const nftCols = [...new Set(live.filter((x) => x.p.kind === 'nft' && !x.p.signed).map((x) => x.p.token))].slice(0, 15);
  const spamCols = new Set((await Promise.all(nftCols.map(async (t) => [t, await alchemyIsSpam(ctx, c, t)] as const))).filter(([, s]) => s === true).map(([t]) => t));
  for (let i = live.length - 1; i >= 0; i--) if (spamCols.has(live[i]!.p.token)) live.splice(i, 1);
  // Who the spenders are.
  const spenders = [...new Set(live.map((x) => x.p.spender))].slice(0, 25);
  const kinds = new Map<string, { type: Approval['spenderType']; name: string | null }>();
  await Promise.all(spenders.map(async (s) => {
    const known = labelOf(s);
    if (known) return kinds.set(s, { type: 'known', name: known });
    const code = await codeAt(ctx, c, s);
    if (code === null) return kinds.set(s, { type: 'unknown', name: null });
    // EIP-7702 delegated wallets carry a 23-byte code starting with ef0100.
    if (code === '0x' || /^0xef0100/i.test(code)) return kinds.set(s, { type: 'wallet', name: null });
    const v = await sourcify(ctx, c, s);
    kinds.set(s, v.data ? { type: 'verified contract', name: v.data.name } : { type: 'unverified contract', name: null });
  }));
  const tokens = [...new Set(live.map((x) => x.p.token))].slice(0, 40);
  const metas = new Map(await Promise.all(tokens.map(async (t) => [t, await tokenMeta(ctx, c, t)] as const)));

  let sanctionedSpender: string | null = null;
  for (const s of spenders.filter((x) => kinds.get(x)?.type !== 'known').slice(0, 8)) {
    try { if ((await screen(ctx, s)).result.verdict === 'SANCTIONED') sanctionedSpender = s; } catch {}
  }

  const approvals: Approval[] = live.map(({ p, amount }) => {
    const m = metas.get(p.token);
    const k = kinds.get(p.spender) ?? { type: 'unknown' as const, name: null };
    const unlimited = p.kind === 'nft' || amount >= UNLIMITED;
    let risk: Approval['risk'] = 'low', why: string | null = null;
    if (p.spender === sanctionedSpender) { risk = 'high'; why = 'spender is on the US OFAC sanctions list'; }
    else if (k.type === 'wallet') { risk = 'high'; why = 'a plain wallet, not a contract, can move these tokens: routers and marketplaces are contracts'; }
    else if (k.type === 'unverified contract' && unlimited) { risk = 'high'; why = 'unlimited access for a contract whose code is not published'; }
    else if (k.type === 'unverified contract' || (k.type === 'unknown' && unlimited)) { risk = 'medium'; why = 'spender code is not published'; }
    else if (unlimited && k.type !== 'known') { risk = 'medium'; why = 'unlimited access for a contract Oculon does not know'; }
    return {
      token: p.token, tokenName: m?.name ?? null, symbol: m?.symbol ?? null, kind: p.kind,
      spender: p.spender, spenderName: k.name, spenderType: k.type,
      amount: p.kind === 'nft' ? 'all NFTs in the collection' : formatUnits(amount, m?.decimals ?? null),
      unlimited, approvedAt: p.at ? new Date(p.at * 1000).toISOString() : null, risk, why,
    };
  }).sort((a, b) => ({ high: 0, medium: 1, low: 2 })[a.risk] - ({ high: 0, medium: 1, low: 2 })[b.risk]);

  const high = approvals.filter((a) => a.risk === 'high'), med = approvals.filter((a) => a.risk === 'medium');
  const unl = approvals.filter((a) => a.unlimited).length;
  const reasons: string[] = [];
  for (const a of [...high, ...med].slice(0, 6)) reasons.push(`${a.symbol ?? a.token.slice(0, 10)} -> ${a.spenderName ?? a.spender.slice(0, 10) + '...'}: ${a.why}`);
  if (unl) reasons.push(`${unl} of ${approvals.length} active approvals are unlimited`);
  if (spam) reasons.push(`${spam} approval events came from transactions this wallet never sent and were ignored (spam tokens fake them)`);
  if (ranked.length > MAX_PAIRS) reasons.push(`the wallet has ${ranked.length} approval pairs; the newest ${MAX_PAIRS} were checked`);
  const risk = Math.min(100, high.length * 45 + med.length * 15 + (unl > 5 ? 10 : 0));
  const verdict: ApprovalsReport['verdict'] = !approvals.length ? (pairs.size ? 'no risky approvals found' : 'no approvals found') : high.length ? 'dangerous approvals' : med.length ? 'risky approvals' : unl ? 'review approvals' : 'no risky approvals found';
  const revokeUrl = `https://revoke.cash/address/${address}?chainId=${c.id}`;
  const advice = high.length || med.length
    ? ['Revoke the flagged approvals now (set the allowance to 0). Revoking costs a small network fee per token.', `A revoke tool that lists the same approvals: ${revokeUrl}`, 'If you did not sign these yourself, move what is left to a new wallet: the seed phrase may be exposed.']
    : approvals.length ? ['Nothing alarming. Unlimited approvals to apps you no longer use are still worth revoking.', `Revoke tool: ${revokeUrl}`] : ['No token or NFT approvals are active on this chain.'];
  const now = ctx.now().toISOString();
  const signals: Signal[] = high.length ? [{ id: signalId('approvals', address, c.key), module: 'approvals', title: `${address.slice(0, 10)} on ${c.label}: ${high.length} dangerous approval${high.length > 1 ? 's' : ''}`, score: Math.min(90, 50 + high.length * 10), entity: `wallet:${address}`, evidence: high.slice(0, 3).map((a) => ({ source: 'etherscan', text: `${a.symbol ?? a.token}: ${a.why}` })), createdAt: now }] : [];
  return {
    module: 'approvals', input: address, generatedAt: now,
    result: { address, chain: c.label, verdict, risk, active: approvals.length, unlimited: unl, checkedPairs: list.length, approvals, reasons, advice, revokeUrl },
    signals, provenance,
  };
}
