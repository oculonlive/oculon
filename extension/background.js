// Oculon Shield service worker: checks the domain of each page a tab opens, sets the toolbar badge,
// sends dangerous pages to a warning page, and answers token checks for the content scripts.
import { apiGet, checkableHost, fromContract, fromUrlCheck, getSettings, reportUrl, SITE_TTL, TOKEN_TTL, CHAINS } from './lib.js';

const session = chrome.storage.session;
const inflight = new Map();
const WARNING = chrome.runtime.getURL('warning.html');

const BADGE = {
  ok: { text: '✓', color: '#0f9d58' },
  warn: { text: '!', color: '#f59e0b' },
  danger: { text: '!', color: '#e11d48' },
  error: { text: '?', color: '#555555' },
  checking: { text: '…', color: '#333333' },
  off: { text: '', color: '#000000' },
};

async function badge(tabId, state) {
  const b = BADGE[state] || BADGE.off;
  try {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
    if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: '#ffffff' });
    await chrome.action.setBadgeText({ tabId, text: b.text });
  } catch {
    /* the tab is gone */
  }
}

async function getOne(key) {
  return (await session.get(key))[key];
}

async function allowlist() {
  return (await getOne('allow')) || [];
}

/** The verdict for a host: from the session cache when fresh, otherwise one /api/url call (shared by callers). */
async function siteVerdict(host) {
  const key = `site:${host}`;
  const hit = await getOne(key);
  if (hit && Date.now() - hit.at < SITE_TTL) return hit.result;
  if (inflight.has(key)) return inflight.get(key);
  const p = apiGet('/api/url', { url: host })
    .then(async (r) => {
      const result = fromUrlCheck(r);
      await session.set({ [key]: { at: Date.now(), result } });
      return result;
    })
    .finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}

async function cachedVerdict(host) {
  const hit = await getOne(`site:${host}`);
  return hit && Date.now() - hit.at < SITE_TTL ? hit.result : null;
}

async function sendToWarning(tabId, url) {
  await chrome.tabs.update(tabId, { url: `${WARNING}?u=${encodeURIComponent(url)}` });
}

async function evaluate(tabId, url) {
  const { siteGuard } = await getSettings();
  const host = checkableHost(url);
  if (!siteGuard || !host) {
    await session.set({ [`tab:${tabId}`]: { host: /^https?:/.test(url) ? safeHost(url) : '', state: siteGuard ? 'skipped' : 'off', url } });
    if (/^https?:/.test(url)) await session.set({ [`prev:${tabId}`]: url });
    return badge(tabId, 'off');
  }
  await session.set({ [`tab:${tabId}`]: { host, state: 'checking', url } });
  await badge(tabId, 'checking');
  let result;
  try {
    result = await siteVerdict(host);
  } catch (e) {
    const cur = await getOne(`tab:${tabId}`);
    if (cur && cur.host === host) {
      await session.set({ [`tab:${tabId}`]: { host, state: 'error', url, error: e.message } });
      await badge(tabId, 'error');
    }
    return;
  }
  const cur = await getOne(`tab:${tabId}`);
  if (!cur || cur.host !== host) return; // the tab moved on while the check ran
  const allowed = (await allowlist()).includes(host);
  await session.set({ [`tab:${tabId}`]: { host, state: result.level, url, result, allowed } });
  await badge(tabId, result.level);
  if (result.level === 'danger' && !allowed) return sendToWarning(tabId, url);
  // Any page that was not blocked is a safe place for "Go back".
  await session.set({ [`prev:${tabId}`]: url });
  if (result.level === 'warn') chrome.tabs.sendMessage(tabId, { type: 'oculon:banner', result }).catch(() => {});
}

const safeHost = (url) => {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
};

// A cached dangerous verdict stops the page before it commits; otherwise the check starts early.
chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0 || d.url.startsWith(WARNING)) return;
  const { siteGuard } = await getSettings();
  const host = siteGuard && checkableHost(d.url);
  if (!host) return;
  const hit = await cachedVerdict(host);
  if (hit && hit.level === 'danger' && !(await allowlist()).includes(host)) {
    await session.set({ [`tab:${d.tabId}`]: { host, state: 'danger', url: d.url, result: hit } });
    await badge(d.tabId, 'danger');
    return sendToWarning(d.tabId, d.url);
  }
  if (!hit) siteVerdict(host).catch(() => {});
});

chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId !== 0) return;
  // Chrome resets a tab's badge on navigation, so the warning page sets it again.
  if (d.url.startsWith(WARNING)) return void badge(d.tabId, 'danger');
  evaluate(d.tabId, d.url).catch(() => {});
});

chrome.tabs.onRemoved.addListener((tabId) => {
  session.remove([`tab:${tabId}`, `prev:${tabId}`]).catch(() => {});
});

const TOKEN_CHAINS = new Set(CHAINS.map((c) => c.key));

async function tokenVerdict(chain, address) {
  if (!TOKEN_CHAINS.has(chain) || !/^0x[0-9a-fA-F]{40}$/.test(address)) return { unsupported: true };
  const key = `tok:${chain}:${address.toLowerCase()}`;
  const hit = await getOne(key);
  if (hit && Date.now() - hit.at < TOKEN_TTL) return { result: hit.result };
  if (inflight.has(key)) return inflight.get(key);
  const p = apiGet('/api/contract', { address, chain })
    .then(async (r) => {
      const result = fromContract(r);
      await session.set({ [key]: { at: Date.now(), result } });
      return { result };
    })
    .catch((e) => ({ error: e.message, status: e.status }))
    .finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const tabId = sender.tab && sender.tab.id;
  (async () => {
    switch (msg && msg.type) {
      case 'oculon:tabState':
        return getOne(`tab:${msg.tabId}`);
      case 'oculon:bannerState': {
        const t = tabId != null && (await getOne(`tab:${tabId}`));
        const dismissed = (await getOne('dismiss')) || [];
        return t && t.state === 'warn' && t.result && !dismissed.includes(t.host) ? { result: t.result } : null;
      }
      case 'oculon:dismissBanner': {
        const t = tabId != null && (await getOne(`tab:${tabId}`));
        if (t && t.host) await session.set({ dismiss: [...new Set([...(((await getOne('dismiss')) || [])), t.host])] });
        return true;
      }
      case 'oculon:warningInfo': {
        const host = checkableHost(msg.url);
        return host ? cachedVerdict(host) : null;
      }
      case 'oculon:proceed': {
        const host = checkableHost(msg.url);
        if (!host || tabId == null) return false;
        await session.set({ allow: [...new Set([...(await allowlist()), host])] });
        await chrome.tabs.update(tabId, { url: msg.url });
        return true;
      }
      case 'oculon:goBack': {
        if (tabId == null) return false;
        const prev = await getOne(`prev:${tabId}`);
        await chrome.tabs.update(tabId, { url: prev || 'chrome://newtab/' });
        return true;
      }
      case 'oculon:clearAllow':
        await session.remove(['allow', 'dismiss']);
        return true;
      case 'oculon:allowCount':
        return (await allowlist()).length;
      case 'oculon:token': {
        const { tokenPills } = await getSettings();
        if (!tokenPills) return { disabled: true };
        const res = await tokenVerdict(String(msg.chain || ''), String(msg.address || ''));
        return res.result ? { ...res, report: await reportUrl(res.result.check) } : res;
      }
      default:
        return null;
    }
  })().then(reply, (e) => reply({ error: e.message }));
  return true;
});
