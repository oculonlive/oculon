import { cleanBase, DEFAULTS, getSettings } from './lib.js';

const $ = (id) => document.getElementById(id);
const status = (t) => { $('status').textContent = t; };

async function load() {
  const s = await getSettings();
  $('siteGuard').checked = s.siteGuard;
  $('tokenPills').checked = s.tokenPills;
  $('apiBase').value = s.apiBase;
  const n = await chrome.runtime.sendMessage({ type: 'oculon:allowCount' }).catch(() => 0);
  $('allowText').textContent = `Sites you chose to continue to from a warning stay allowed until the browser closes. Allowed now: ${n || 0}.`;
}

for (const id of ['siteGuard', 'tokenPills']) {
  $(id).addEventListener('change', async () => {
    await chrome.storage.sync.set({ [id]: $(id).checked });
    status('Saved.');
  });
}

async function saveBase(value) {
  const raw = String(value).trim().replace(/\/+$/, '');
  const base = cleanBase(raw);
  if (raw && base !== raw) return status('That is not a valid base URL. Use something like https://app.oculon.live');
  const origin = `${new URL(base).origin}/*`;
  const known = /^https:\/\/(app\.)?oculon\.live$/.test(base);
  if (!known) {
    // Needs a permission click, so it runs inside the click handler.
    const ok = await chrome.permissions.request({ origins: [origin] }).catch(() => false);
    if (!ok) return status('Permission to reach that server was not granted. Nothing changed.');
  }
  await chrome.storage.sync.set({ apiBase: base });
  $('apiBase').value = base;
  status(`Saved. Checks now go to ${base}.`);
}

$('save').addEventListener('click', () => saveBase($('apiBase').value));
$('reset').addEventListener('click', () => saveBase(DEFAULTS.apiBase));
$('clear').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'oculon:clearAllow' });
  status('Allowed sites and dismissed banners cleared.');
  load();
});

load();
