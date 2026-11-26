import { CHAINS, checkInput, classify, LEVEL_TEXT, reportUrl } from './lib.js';

const $ = (id) => document.getElementById(id);

function paint(prefix, card, r, opts = {}) {
  card.classList.remove('ok', 'warn', 'danger');
  if (r && r.level) card.classList.add(r.level);
  $(`${prefix}-verdict`).textContent = r ? `${LEVEL_TEXT[r.level] || ''}${r.verdict ? `: ${r.verdict}` : ''}` : opts.text || '';
  $(`${prefix}-score`).textContent = r && r.score != null ? `risk ${r.score}/100` : '';
  const ul = $(`${prefix}-reasons`);
  ul.textContent = '';
  for (const t of (r && r.reasons) || []) {
    const li = document.createElement('li');
    li.textContent = t;
    ul.appendChild(li);
  }
  if (r && r.advice && r.advice.length) {
    const li = document.createElement('li');
    li.className = 'muted';
    li.textContent = r.advice[0];
    ul.appendChild(li);
  }
  const more = $(`${prefix}-more`);
  more.textContent = '';
  if (r && r.check) {
    reportUrl(r.check).then((u) => {
      if (!u) return;
      const a = document.createElement('a');
      a.href = u;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = 'Open the full report on Oculon';
      more.appendChild(a);
    });
  }
}

async function showSite() {
  const card = $('site');
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const st = tab && (await chrome.runtime.sendMessage({ type: 'oculon:tabState', tabId: tab.id }).catch(() => null));
  if (!st) return paint('site', card, null, { text: 'Not checked yet. Reload the page to check it.' });
  $('site-host').textContent = st.host || '';
  if (st.state === 'off') return paint('site', card, null, { text: 'Site guard is off' });
  if (st.state === 'skipped') return paint('site', card, null, { text: 'Not checked (well-known, local or browser page)' });
  if (st.state === 'checking') return paint('site', card, null, { text: 'Checking...' });
  if (st.state === 'error') return paint('site', card, null, { text: `Could not check: ${st.error || 'unknown error'}` });
  paint('site', card, st.result);
  $('site-host').textContent = `${st.host}${st.allowed ? ' (you chose to continue for this session)' : ''}`;
}

for (const c of CHAINS) {
  const o = document.createElement('option');
  o.value = c.key;
  o.textContent = c.label;
  $('chain').appendChild(o);
}

$('q').addEventListener('input', () => {
  const c = classify($('q').value);
  $('evm').classList.toggle('hidden', !c || c.kind !== 'evm');
});

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const card = $('out');
  card.classList.remove('hidden');
  $('out-subject').textContent = '';
  paint('out', card, null, { text: 'Checking...' });
  $('go').disabled = true;
  try {
    const as = document.querySelector('input[name=as]:checked').value;
    const r = await checkInput($('q').value, { chain: $('chain').value, as });
    $('out-subject').textContent = [r.subject, r.chain].filter(Boolean).join(' · ');
    paint('out', card, r);
  } catch (err) {
    paint('out', card, null, { text: err.message });
  } finally {
    $('go').disabled = false;
  }
});

showSite();
