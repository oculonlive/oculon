/**
 * Contract risk: what the people behind a token can still do to holders.
 *   Code: the verified ABI (Sourcify, then Etherscan), or for unverified contracts the function selectors found
 *     in the deployed bytecode, decoded through the public signature databases. Owner-only powers are grouped:
 *     minting, blacklists, trading switches, tax changes, wallet limits, balance changes, withdrawals, upgrades.
 *   Control: who owns it now (owner() on chain; renounced when it is the zero or dead address), and for proxies
 *     the implementation and admin from the EIP-1967 storage slots.
 *   Market: holder concentration and locked liquidity (GoPlus, keyless), the main pool and its age (DexScreener).
 * Works on Ethereum, Base, BNB Chain, Arbitrum and Polygon. A function existing is not proof it will be used;
 * the report says what is possible, not what will happen.
 */
import type { Ctx } from '../core/context.js';
import { enc } from '../core/context.js';
import type { ModuleResult, Provenance, Signal } from '../core/types.js';
import { signalId } from '../core/text.js';
import { bytecodeSelectors, codeAt, DEAD, ethCall, etherscanSource, evmChain, isAddr, rpcCall, sourcify, tokenMeta, wordAddr, type AbiItem, type Verified } from '../sources/evm.js';
import { dexPairs } from '../sources/onchain.js';
import { decodeSelectors, methodName } from '../sources/signatures.js';

export interface Power { power: string; functions: string[]; weight: number }

export interface ContractReport {
  address: string;
  chain: string;
  name: string | null;
  symbol: string | null;
  verified: boolean;
  verifiedBy: string | null;
  contractName: string | null;
  verdict: 'dangerous contract' | 'risky contract' | 'caution' | 'no major risks found';
  risk: number;
  owner: string | null;
  ownerRenounced: boolean | null;
  proxy: { implementation: string | null; admin: string | null } | null;
  powers: Power[];
  holders: { count: number | null; top10Percent: number | null; creatorPercent: number | null; ownerPercent: number | null } | null;
  liquidity: { usd: number | null; pair: string | null; dex: string | null; createdAt: string | null; lockedPercent: number | null } | null;
  reasons: string[];
  notes: string[];
  advice: string[];
}

const POWERS: [string, RegExp, number][] = [
  ['can mint new tokens', /^(mint|_mint|mintto|minttokens|issue|mintfor|createtokens)$/, 25],
  ['can block wallets (blacklist)', /blacklist|blocklist|denylist|^(addbots?|setbots?|blockbots?|markbots?|setbot|ban|banaddress|freeze|freezeaccount|setsniper|addsniper|setblocked|block)$/, 25],
  ['can stop trading or transfers', /^(pause|setpaused|settradingenabled|settradingopen|enabletrading|disabletrading|settrading|toggletrading|setswapenabled|stoptrading|lock|settransferenabled)$/, 15],
  ['can change buy and sell taxes', /^(setfees?|settax(es)?|updatefees?|setbuyfees?|setsellfees?|setbuytax|setselltax|updatebuyfees|updatesellfees|settaxfee|setliquidityfee|setmarketingfee|setswapfee|settotalfees?|setfeepercent|setreflectionfee)$/, 20],
  ['can limit how much a wallet holds or sells', /^(setmaxtx(amount|percent)?|setmaxwallet(size|amount|percent)?|setmaxtransaction(amount)?|updatemaxtx(amount)?|updatemaxwallet(amount)?|setlimits|setmaxsell|setmaxbuy|setmaxtxpercent)$/, 10],
  ['can exempt chosen wallets from taxes and limits', /^(excludefromfees?|setexcluded(fromfee)?|includeinfee|setisfeeexempt|setfeeexempt|excludefrommaxtransaction|setiswhitelisted|whitelist|addtowhitelist|setwhitelist)$/, 5],
  ['can change balances directly', /^(setbalance|setbalances|rebase|burnfrom?owner|adminburn|wipe|destroyblackfunds|reflect|setrebase)$/, 30],
  ['can withdraw tokens or ETH held by the contract', /^(withdraw|withdrawall|withdrawtokens?|rescue(tokens?|eth|erc20)?|recover(tokens?|eth|erc20)?|sweep|clearstucktokens?|claimstuck(tokens|balance)?|emergencywithdraw|manualswap|manualsend)$/, 5],
  ['can replace the contract code (upgradeable)', /^(upgradeto|upgradetoandcall|setimplementation|upgrade|changeimplementation)$/, 25],
  ['can self-destruct', /^(selfdestruct|kill|destroy|destruct)$/, 25],
];
const OWNER_FNS = /^(owner|getowner|renounceownership|transferownership|acceptownership)$/;

const IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const ADMIN_SLOT = '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103';

const writeFns = (abi: AbiItem[]) => abi.filter((x) => x.type === 'function' && x.stateMutability !== 'view' && x.stateMutability !== 'pure').map((x) => x.name ?? '').filter(Boolean);

export function powersOf(names: string[]): Power[] {
  const out: Power[] = [];
  for (const [power, re, weight] of POWERS) {
    const fns = [...new Set(names.filter((n) => re.test(n.toLowerCase())))];
    if (fns.length) out.push({ power, functions: fns.slice(0, 6), weight });
  }
  return out;
}

interface GoPlus { holder_count?: string; creator_percent?: string; owner_percent?: string; holders?: { address: string; percent: string; is_locked?: number; is_contract?: number; tag?: string }[]; lp_holders?: { address: string; percent: string; is_locked?: number; tag?: string }[] }

export async function contractRisk(ctx: Ctx, input: string, opts: { chain?: string } = {}): Promise<ModuleResult<ContractReport>> {
  const address = input.trim().toLowerCase();
  if (!isAddr(address)) throw new Error('give a contract address: 0x followed by 40 hex characters');
  const c = evmChain(opts.chain);
  const provenance: Provenance[] = [];
  const code = await codeAt(ctx, c, address);
  if (code === null) throw new Error(`could not read the contract from ${c.label}`);
  if (code === '0x') throw new Error(`${address} is not a contract on ${c.label} (no code at this address)`);
  const reasons: string[] = [], notes: string[] = [];

  // Verified code, also for the implementation behind a proxy.
  let v: Verified | null = (await sourcify(ctx, c, address).then((r) => (provenance.push(r.prov), r.data)));
  if (!v) v = await etherscanSource(ctx, c, address).then((r) => (provenance.push(r.prov), r.data));
  const [implSlot, adminSlot] = await Promise.all([rpcCall<string>(ctx, c, 'eth_getStorageAt', [address, IMPL_SLOT, 'latest'], 600), rpcCall<string>(ctx, c, 'eth_getStorageAt', [address, ADMIN_SLOT, 'latest'], 600)]);
  const slotAddr = (h: string | null) => (h && /[1-9a-f]/i.test(h.slice(2)) ? wordAddr(h, 0) : null);
  const impl = v?.proxy?.implementations[0]?.address?.toLowerCase() ?? slotAddr(implSlot.data);
  const admin = slotAddr(adminSlot.data);
  let names: string[] = [];
  if (v) names.push(...writeFns(v.abi));
  if (impl) {
    let iv = (await sourcify(ctx, c, impl)).data;
    if (!iv) iv = (await etherscanSource(ctx, c, impl)).data;
    if (iv) names.push(...writeFns(iv.abi));
    else {
      const icode = await codeAt(ctx, c, impl);
      if (icode && icode !== '0x') names.push(...await selectorNames(ctx, icode));
    }
  }
  if (!v) {
    names.push(...await selectorNames(ctx, code));
    reasons.push('source code is not verified: nobody can read what it does (functions below come from its bytecode)');
  }
  names = [...new Set(names)];
  const powers = powersOf(names);
  if (impl || v?.proxy?.isProxy) {
    if (!powers.some((p) => p.power.startsWith('can replace'))) powers.push({ power: 'can replace the contract code (upgradeable)', functions: ['proxy'], weight: 25 });
  }

  // Ownership.
  const [o1, o2] = await Promise.all([ethCall(ctx, c, address, '0x8da5cb5b', 300), ethCall(ctx, c, address, '0x893d20e8', 300)]);
  const ownRaw = [o1.data, o2.data].find((d) => d && d.length >= 66) ?? null;
  const owner = ownRaw ? wordAddr(ownRaw, 0) : null;
  const hasOwnerFns = names.some((n) => OWNER_FNS.test(n.toLowerCase()));
  const ownerRenounced = owner ? DEAD.test(owner) : hasOwnerFns ? null : null;
  const ownerActive = Boolean(owner && !DEAD.test(owner)) || Boolean(admin && !DEAD.test(admin));

  // Market: holders and liquidity.
  let holders: ContractReport['holders'] = null, lockedPercent: number | null = null;
  if (c.key !== 'robinhood') {
    const g = await ctx.http.get<{ result?: Record<string, GoPlus> }>(`https://api.gopluslabs.io/api/v1/token_security/${c.id}?contract_addresses=${enc(address)}`, { source: 'goplus', ttlSec: 1800 });
    provenance.push(g.prov);
    const d = g.data?.result?.[address];
    if (d) {
      const top = (d.holders ?? []).filter((h) => !h.is_locked && !DEAD.test(h.address) && !/lock|burn|dead|pair|pool/i.test(h.tag ?? '')).slice(0, 10);
      holders = { count: d.holder_count ? Number(d.holder_count) : null, top10Percent: top.length ? Math.round(top.reduce((s, h) => s + Number(h.percent), 0) * 1000) / 10 : null, creatorPercent: d.creator_percent ? Math.round(Number(d.creator_percent) * 1000) / 10 : null, ownerPercent: d.owner_percent ? Math.round(Number(d.owner_percent) * 1000) / 10 : null };
      const lp = d.lp_holders ?? [];
      if (lp.length) lockedPercent = Math.round(lp.filter((h) => h.is_locked || DEAD.test(h.address)).reduce((s, h) => s + Number(h.percent), 0) * 1000) / 10;
    }
  }
  const pairs = await dexPairs(ctx, address, c.key);
  provenance.push(pairs.prov);
  const main = pairs.data?.[0] ?? null;
  const liquidity: ContractReport['liquidity'] = main || lockedPercent !== null ? { usd: main?.liquidityUsd ?? null, pair: main?.pair ?? null, dex: main?.dex ?? null, createdAt: main?.createdAt ?? null, lockedPercent } : null;

  // Score.
  let risk = 0;
  const live = ownerActive || !v;
  for (const p of powers) {
    const w = live ? p.weight : Math.round(p.weight / 4);
    risk += w;
    reasons.push(`${p.power}: ${p.functions.join(', ')}${live ? '' : ' (owner renounced)'}`);
  }
  if (!v) risk += 25;
  if (owner && !DEAD.test(owner)) notes.push(`Owner ${owner} still controls the owner-only functions.`);
  if (ownerRenounced) notes.push('Ownership is renounced: owner-only functions can no longer be called, unless another role or a proxy admin exists.');
  if (admin && !DEAD.test(admin)) reasons.push(`proxy admin ${admin} can upgrade the code at any time`);
  if (holders?.top10Percent !== null && holders?.top10Percent !== undefined && holders.top10Percent >= 50) { risk += holders.top10Percent >= 80 ? 25 : 15; reasons.push(`top 10 wallets hold ${holders.top10Percent}% of the supply`); }
  if (holders?.creatorPercent && holders.creatorPercent >= 10) { risk += 10; reasons.push(`the creator still holds ${holders.creatorPercent}%`); }
  if (liquidity) {
    if (liquidity.usd !== null && liquidity.usd < 10_000) { risk += 15; reasons.push(`thin liquidity: about $${Math.round(liquidity.usd).toLocaleString('en-US')} in the main pool`); }
    // LP locks only mean something for young, small pools (big V3 pools hold no LP tokens at all).
    if (lockedPercent !== null && lockedPercent < 50 && (liquidity.usd ?? 0) < 1_000_000) { risk += 15; reasons.push(`only ${lockedPercent}% of the pool tokens are locked or burned: liquidity can be pulled`); }
    if (liquidity.createdAt && Date.now() - Date.parse(liquidity.createdAt) < 3 * 86_400_000) { risk += 10; reasons.push(`the main pool is less than 3 days old`); }
  } else notes.push('No DEX pool found for this token.');
  risk = Math.min(100, risk);
  // Stablecoins and wrapped assets are built with mint, freeze and upgrade powers on purpose.
  if ((holders?.count ?? 0) >= 50_000 && (liquidity?.usd ?? 0) >= 5_000_000 && risk >= 40) {
    risk = 39;
    notes.push('Large, established token: owner powers like these are typical of a centrally issued token (stablecoins, wrapped assets). They still mean the issuer can mint, freeze or upgrade.');
  }
  const verdict: ContractReport['verdict'] = risk >= 70 ? 'dangerous contract' : risk >= 40 ? 'risky contract' : risk >= 15 ? 'caution' : 'no major risks found';
  const meta = await tokenMeta(ctx, c, address);
  const advice = verdict === 'no major risks found'
    ? ['No owner powers or market red flags found. That does not make it a good investment; it only means the code and market look ordinary.']
    : ['Do not buy more than you can lose. Owner powers listed above can be used at any time without warning.', 'Check whether you can sell: oculon honeypot <address>', 'Set a limited approval instead of unlimited when you trade it.'];
  const now = ctx.now().toISOString();
  const signals: Signal[] = risk >= 70 ? [{ id: signalId('contract', address, c.key), module: 'contract', title: `${meta.symbol ?? address.slice(0, 10)} on ${c.label}: ${verdict}`, score: risk, entity: `token:${address}`, evidence: reasons.slice(0, 4).map((t) => ({ source: v?.source ?? 'bytecode', text: t })), createdAt: now }] : [];
  return {
    module: 'contract', input: address, generatedAt: now,
    result: { address, chain: c.label, name: meta.name, symbol: meta.symbol, verified: Boolean(v), verifiedBy: v?.source ?? null, contractName: v?.name ?? null, verdict, risk, owner, ownerRenounced, proxy: impl || admin ? { implementation: impl, admin } : null, powers, holders, liquidity, reasons, notes, advice },
    signals, provenance,
  };
}

async function selectorNames(ctx: Ctx, code: string): Promise<string[]> {
  const sels = bytecodeSelectors(code).slice(0, 160);
  if (!sels.length) return [];
  const d = await decodeSelectors(ctx, sels).catch(() => ({}) as Record<string, string | null>);
  return Object.values(d).map((s) => methodName(s)).filter((s): s is string => Boolean(s));
}
