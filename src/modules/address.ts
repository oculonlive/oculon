/**
 * Crypto address check without API keys: which chain the address belongs to (from its format), whether it is
 * on the US OFAC sanctions list, and its age, balance and activity from free explorers (mempool.space for
 * Bitcoin, Blockscout for Ethereum and Robinhood Chain, the public Solana RPC), victims' scam reports
 * (Chainabuse, free key) and the ScamSniffer scam address list. Useful before you send funds to an address
 * someone gave you in a chat.
 */
import type { Ctx } from '../core/context.js';
import type { ModuleResult, Provenance } from '../core/types.js';
import { screen } from './sanctions.js';
import { key } from '../core/keys.js';
import { chainabuse, type AbuseReports } from '../sources/chainabuse.js';
import { ensurePhishLists, phishAddress } from '../sources/phishlists.js';

export interface AddressReport {
  address: string;
  chain: 'bitcoin' | 'evm' | 'solana' | 'tron' | 'unknown';
  format: string;
  network: string | null;
  activity: { txCount: number | null; balance: string | null; firstSeen: string | null; isContract: boolean | null; label: string | null } | null;
  sanctioned: boolean | null;
  sanctionHits: string[];
  /** Scam reports filed by victims (Chainabuse). */
  reports: AbuseReports | null;
  warnings: string[];
  advice: string[];
}

const B58 = /^[1-9A-HJ-NP-Za-km-z]+$/;

export function detectChain(a: string): { chain: AddressReport['chain']; format: string } {
  if (/^0x[0-9a-fA-F]{40}$/.test(a)) return { chain: 'evm', format: 'EVM (Ethereum, Base, Robinhood Chain and other EVM chains)' };
  if (/^(bc1|tb1)[02-9ac-hj-np-z]{11,71}$/.test(a.toLowerCase())) return { chain: 'bitcoin', format: a.toLowerCase().startsWith('bc1p') ? 'Bitcoin Taproot (bech32m)' : 'Bitcoin SegWit (bech32)' };
  if (/^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/.test(a)) return { chain: 'bitcoin', format: a.startsWith('1') ? 'Bitcoin legacy (P2PKH)' : 'Bitcoin script (P2SH)' };
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(a)) return { chain: 'tron', format: 'Tron (TRC-20 USDT lives here)' };
  if (B58.test(a) && a.length >= 32 && a.length <= 44) return { chain: 'solana', format: 'Solana' };
  return { chain: 'unknown', format: 'not a recognized address format' };
}

export async function addressCheck(ctx: Ctx, input: string, opts: { network?: string } = {}): Promise<ModuleResult<AddressReport>> {
  const address = input.trim();
  if (!address) throw new Error('give a crypto address');
  const { chain, format } = detectChain(address);
  if (chain === 'unknown') throw new Error(`not a crypto address: ${address.slice(0, 60)}`);
  const provenance: Provenance[] = [];
  const warnings: string[] = [];
  let activity: AddressReport['activity'] = null;
  let network: string | null = null;

  if (chain === 'bitcoin') {
    network = 'Bitcoin';
    const r = await ctx.http.get<{ chain_stats?: { tx_count?: number; funded_txo_sum?: number; spent_txo_sum?: number } }>(`https://mempool.space/api/address/${address}`, { source: 'mempool-space', ttlSec: 600 });
    provenance.push(r.prov);
    const s = r.data?.chain_stats;
    if (s) activity = { txCount: s.tx_count ?? 0, balance: `${(((s.funded_txo_sum ?? 0) - (s.spent_txo_sum ?? 0)) / 1e8).toFixed(8)} BTC`, firstSeen: null, isContract: false, label: null };
  } else if (chain === 'evm') {
    const rh = /^(rh|robinhood)$/i.test(opts.network ?? '');
    network = rh ? 'Robinhood Chain' : 'Ethereum';
    const bk = key('BLOCKSCOUT_API_KEY');
    const base = rh ? 'https://api.blockscout.com/4663/api/v2' : 'https://eth.blockscout.com/api/v2';
    const q = rh && bk ? `?apikey=${bk}` : '';
    const r = await ctx.http.get<{ coin_balance?: string; is_contract?: boolean; creator_address_hash?: string | null; ens_domain_name?: string; name?: string; public_tags?: { display_name?: string }[] }>(`${base}/addresses/${address}${q}`, { source: 'blockscout', ttlSec: 900 });
    provenance.push({ ...r.prov, url: r.prov.url.replace(/apikey=[^&]+/, 'apikey=***') });
    const c = await ctx.http.get<{ transactions_count?: string }>(`${base}/addresses/${address}/counters${q}`, { source: 'blockscout', ttlSec: 900 });
    provenance.push({ ...c.prov, url: c.prov.url.replace(/apikey=[^&]+/, 'apikey=***') });
    if (r.data || r.prov.note === 'HTTP 404') {
      const d = r.data ?? {};
      activity = { txCount: c.data?.transactions_count ? Number(c.data.transactions_count) : 0, balance: d.coin_balance ? `${(Number(BigInt(d.coin_balance) / 10n ** 12n) / 1e6).toFixed(6)} ETH` : '0 ETH', firstSeen: null,
        // A wallet with an EIP-7702 delegation also has code, but no creator: only deployed contracts have one.
        isContract: d.is_contract === undefined ? null : Boolean(d.is_contract && d.creator_address_hash),
        label: d.ens_domain_name ?? d.public_tags?.[0]?.display_name ?? d.name ?? null };
    }
  } else if (chain === 'solana') {
    network = 'Solana';
    const r = await ctx.http.postBytes('https://api.mainnet-beta.solana.com', new TextEncoder().encode(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getBalance', params: [address] })), { source: 'solana-rpc', headers: { 'content-type': 'application/json' }, timeoutMs: 20_000 });
    provenance.push(r.prov);
    let lamports: number | null = null;
    try { lamports = r.data ? Number((JSON.parse(r.data.toString('utf8')) as { result?: { value?: number } }).result?.value ?? NaN) : null; } catch { lamports = null; }
    if (lamports !== null && Number.isFinite(lamports)) activity = { txCount: null, balance: `${(lamports / 1e9).toFixed(6)} SOL`, firstSeen: null, isContract: null, label: null };
  } else {
    network = 'Tron';
  }

  if (activity && activity.txCount === 0) warnings.push('this address has never been used: double-check it with the person you are paying through another channel');
  if (activity?.isContract) warnings.push('this is a smart contract, not a personal wallet: sending to it directly can lose the funds');

  // Sanctions: the US OFAC SDN list includes crypto addresses (Bitcoin, EVM, Tron and more).
  let sanctioned: boolean | null = null;
  const hits: string[] = [];
  try {
    const s = await screen(ctx, address);
    provenance.push(...s.provenance.slice(0, 2));
    sanctioned = s.result.verdict === 'SANCTIONED';
    for (const h of s.result.hits.slice(0, 3)) hits.push(JSON.stringify(h).slice(0, 160));
    if (sanctioned) warnings.unshift('this address is on the US OFAC sanctions list: sending to it can be illegal');
    else if (s.result.verdict === 'EXPOSED') warnings.push('this address has traded directly with a sanctioned address');
  } catch { /* the list is optional here */ }

  // Victims' reports and known scam addresses.
  let reports: AbuseReports | null = null;
  try {
    const ca = await chainabuse(ctx, 'address', address);
    if (ca.prov) provenance.push(ca.prov);
    reports = ca.data;
    // Anyone can file a report; one or two unverified ones (famous addresses collect some) are kept in the
    // result but do not raise a warning.
    if (reports?.count && (reports.trusted > 0 || reports.count >= 3)) warnings.unshift(`${reports.count} scam report${reports.count > 1 ? 's' : ''} filed by victims on Chainabuse${reports.trusted ? ` (${reports.trusted} verified by Chainabuse)` : ""}${reports.categories.length ? ` (${reports.categories.join(', ')})` : ''}${reports.latest ? `, latest ${reports.latest.slice(0, 10)}` : ''}`);
  } catch {}
  if (chain === 'evm') {
    try {
      await ensurePhishLists(ctx);
      const listed = phishAddress(ctx, address);
      if (listed) warnings.unshift(`on the ${listed}`);
    } catch {}
  }

  const advice = warnings.length
    ? ['Do not send funds until you have confirmed the address with the recipient through a channel you already trust.']
    : ['Nothing alarming found. Still send a small test amount first, and never send to an address someone pushes on you in a chat.'];
  return { module: 'address', input: address, generatedAt: ctx.now().toISOString(), result: { address, chain, format, network, activity, sanctioned, sanctionHits: hits, reports, warnings, advice }, signals: [], provenance };
}
