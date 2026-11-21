/**
 * Feature switches.
 *
 * On-chain features (Robinhood Chain pools, token and deployer checks through Heron; wallet and token
 * checks through Magpie) are paused by default. The code stays in place and keeps its tests; setting
 * OCULON_ONCHAIN=1 turns the commands, MCP tools, agent tools, schedule task, watch kinds and web
 * sections back on.
 */
export function onchainEnabled(): boolean {
  return process.env.OCULON_ONCHAIN === '1';
}

/** CLI commands that belong to the on-chain features. */
export const ONCHAIN_COMMANDS = new Set(['rh', 'deployer', 'wallet', 'token', 'defi', 'protocol']);

/** MCP and agent tools that belong to the on-chain features. */
export const ONCHAIN_TOOLS = new Set(['oculon_wallet', 'oculon_token', 'oculon_robinhood', 'oculon_robinhood_token', 'oculon_robinhood_deployer', 'oculon_defi', 'oculon_protocol']);

/** Modules whose signals are on-chain findings. */
export const ONCHAIN_MODULES = new Set(['heron', 'magpie', 'defi']);

/** Watchlist kinds that run on-chain checks. */
export const ONCHAIN_WATCH_KINDS = new Set(['wallet', 'token']);

/** Graph entities created by on-chain checks (tokens, deployers, wallets). */
export function isOnchainEntity(id: string): boolean {
  return /^event:(token:|deployer:)|^(wallet|token):/i.test(id);
}

export const ONCHAIN_PAUSED_MESSAGE = 'On-chain features (Robinhood Chain, wallet and token checks, DeFi) are paused in this build. Set OCULON_ONCHAIN=1 to turn them back on.';

/** Sources and hosts that only serve the on-chain features. */
export function isOnchainSource(name: string): boolean {
  return /defillama|llama\.fi|alternative\.me|blockscout|geckoterminal|robinhood|dexscreener|zerion|etherscan|helius|webacy|goplus|codex|4byte|openchain|eth-labels/i.test(name);
}
