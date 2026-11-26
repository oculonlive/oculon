import { reportUrl } from './lib.js';

const $ = (id) => document.getElementById(id);
const target = new URLSearchParams(location.search).get('u') || '';
let host = '';
try {
  const u = new URL(target);
  if (u.protocol === 'http:' || u.protocol === 'https:') host = u.hostname;
} catch {
  /* bad link */
}
$('host').textContent = host || 'unknown site';
if (!host) $('go').disabled = true;

chrome.runtime.sendMessage({ type: 'oculon:warningInfo', url: target }).then(async (r) => {
  if (!r) return;
  $('verdict').textContent = `Dangerous: ${r.verdict}`;
  if (r.score != null) $('score').textContent = `risk ${r.score}/100`;
  for (const t of r.reasons || []) {
    const li = document.createElement('li');
    li.textContent = t;
    $('reasons').appendChild(li);
  }
  const u = await reportUrl(r.check);
  if (u) {
    const a = document.createElement('a');
    a.href = u;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = 'See the full Oculon report and its sources';
    $('more').appendChild(a);
  }
}).catch(() => {});

$('back').addEventListener('click', () => chrome.runtime.sendMessage({ type: 'oculon:goBack' }));
$('go').addEventListener('click', () => {
  if (host) chrome.runtime.sendMessage({ type: 'oculon:proceed', url: target });
});
