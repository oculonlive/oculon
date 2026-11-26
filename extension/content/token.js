// Token pages on DexScreener, Uniswap and the Robinhood Chain explorers: read the token address from the
// URL (or, on DexScreener pair pages, from the token's explorer link), ask the service worker for the
// Oculon contract check, and show a small floating pill with the verdict and risk score.
(() => {
  if (window.top !== window || window.__oculonToken) return;
  window.__oculonToken = true;

  const ADDR = /^0x[0-9a-fA-F]{40}$/;
  const DEX_CHAINS = { ethereum: 'eth', base: 'base', bsc: 'bsc', arbitrum: 'arbitrum', polygon: 'polygon', robinhood: 'robinhood' };
  const UNI_CHAINS = { ethereum: 'eth', base: 'base', bnb: 'bsc', arbitrum: 'arbitrum', polygon: 'polygon', robinhood: 'robinhood' };

  /** { chain, address } for the current page, null when this page is not a supported token page,
   *  or 'wait' when the address is not on the page yet. */
  function target() {
    const h = location.hostname;
    const parts = location.pathname.split('/').filter(Boolean);
    if (h === 'robin.etherscan.io' || h === 'robinhoodchain.blockscout.com' || h === 'robinhood.blockscout.com') {
      return parts[0] === 'token' && ADDR.test(parts[1] || '') ? { chain: 'robinhood', address: parts[1] } : null;
    }
    if (h === 'app.uniswap.org') {
      // /explore/tokens/<chain>/<address>
      const i = parts.indexOf('tokens');
      if (parts[0] !== 'explore' || i !== 1) return null;
      const chain = UNI_CHAINS[(parts[2] || '').toLowerCase()];
      return chain && ADDR.test(parts[3] || '') ? { chain, address: parts[3] } : null;
    }
    if (h === 'dexscreener.com') {
      // /<chain>/<pair id>: the URL names the pair, so the token comes from the page's explorer link.
      const chain = DEX_CHAINS[(parts[0] || '').toLowerCase()];
      if (!chain || !parts[1] || !/^0x[0-9a-fA-F]{40,64}$/.test(parts[1])) return null;
      const pair = parts[1].toLowerCase();
      for (const a of document.querySelectorAll('a[href*="/token/0x"]')) {
        const m = /\/token\/(0x[0-9a-fA-F]{40})(?![0-9a-fA-F])/.exec(a.getAttribute('href') || '');
        if (m && m[1].toLowerCase() !== pair) return { chain, address: m[1] };
      }
      return 'wait';
    }
    return null;
  }

  let host = null;
  let shown = '';
  let waited = 0;

  function remove() {
    if (host) host.remove();
    host = null;
  }

  const COLORS = { ok: '#16c784', warn: '#f59e0b', danger: '#ff3b5c', none: '#7f8a8f' };

  function render(state) {
    remove();
    host = document.createElement('div');
    host.style.cssText = 'all:initial;position:fixed;right:16px;bottom:16px;z-index:2147483647';
    const root = host.attachShadow({ mode: 'closed' });
    const color = COLORS[state.level] || COLORS.none;
    root.innerHTML = `
      <style>
        *{box-sizing:border-box}
        .w{font:13px/1.4 "Space Grotesk","Segoe UI",system-ui,-apple-system,sans-serif;color:#e8e8e8;display:flex;flex-direction:column;align-items:flex-end;gap:8px}
        .p{display:flex;align-items:center;gap:8px;background:#000;border:1px solid ${color};border-radius:999px;padding:6px 12px 6px 8px;cursor:pointer;box-shadow:0 6px 20px rgba(0,0,0,.5);font:inherit;color:inherit}
        .p:hover{background:#0a0f12}
        .m{width:16px;height:16px;flex:none}
        .d{width:8px;height:8px;border-radius:50%;background:${color};flex:none}
        .v{font-weight:600;color:${color}}
        .s{color:#9aa4a8;font-variant-numeric:tabular-nums}
        .c{display:none;width:320px;max-width:calc(100vw - 32px);max-height:60vh;overflow:auto;background:#05070a;border:1px solid #1d2a30;border-radius:12px;padding:12px 14px;box-shadow:0 10px 30px rgba(0,0,0,.6)}
        .c.o{display:block}
        .t{font-weight:600;margin-bottom:4px}
        .k{font-size:11px;color:#7f8a8f;text-transform:uppercase;letter-spacing:.08em;margin:10px 0 4px}
        ul{margin:0;padding-left:18px;color:#c9c9c9}
        li{margin:2px 0}
        a{color:#00f0ff;text-decoration:none}
        a:hover{text-decoration:underline}
        .r{display:flex;justify-content:space-between;align-items:center;margin-top:10px;gap:8px}
        .x{background:none;border:0;color:#7f8a8f;font:inherit;font-size:12px;cursor:pointer;padding:0}
        .x:hover{color:#fff}
      </style>
      <div class="w">
        <div class="c" role="dialog" aria-label="Oculon token check">
          <div class="t"></div>
          <div class="sub s"></div>
          <div class="k rk">Why</div><ul class="re"></ul>
          <div class="k ak">Advice</div><ul class="ad"></ul>
          <div class="r"><a class="fr" target="_blank" rel="noopener noreferrer">Full report</a><button class="x">Hide on this page</button></div>
        </div>
        <button class="p" title="Oculon token check">
          <svg class="m" viewBox="212 212 600 600" aria-hidden="true"><path fill="#00f0ff" d="M512 212 H348 Q212 212 212 348 V676 Q212 812 348 812 H676 Q812 812 812 676 V512 H680 V630 Q680 680 630 680 H394 Q344 680 344 630 V394 Q344 344 394 344 H512 Z"/><path fill="#00f0ff" d="M586 212 H676 Q812 212 812 348 V438 Q812 472 778 472 H586 Q552 472 552 438 V246 Q552 212 586 212 Z"/></svg>
          <span class="d"></span><span class="v"></span><span class="s"></span>
        </button>
      </div>`;
    const $ = (s) => root.querySelector(s);
    $('.v').textContent = state.label;
    $('.s').textContent = state.score != null ? `${state.score}/100` : '';
    $('.t').textContent = state.title || 'Oculon token check';
    $('.sub').textContent = state.sub || '';
    const fill = (ul, k, items) => {
      if (!items || !items.length) { $(ul).remove(); $(k).remove(); return; }
      for (const r of items.slice(0, 8)) { const li = document.createElement('li'); li.textContent = r; $(ul).appendChild(li); }
    };
    fill('.re', '.rk', state.reasons);
    fill('.ad', '.ak', state.advice);
    if (state.report) $('.fr').href = state.report; else $('.fr').remove();
    $('.p').addEventListener('click', () => $('.c').classList.toggle('o'));
    $('.x').addEventListener('click', () => { remove(); shown = `hidden:${location.href}`; });
    (document.body || document.documentElement).appendChild(host);
  }

  async function run() {
    if (shown === `hidden:${location.href}`) return;
    const t = target();
    if (t === 'wait') {
      if (++waited > 15) remove(); // no token link after ~15s: stay out of the way
      return;
    }
    waited = 0;
    if (!t) { remove(); shown = ''; return; }
    const key = `${t.chain}:${t.address.toLowerCase()}`;
    if (shown === key) return;
    shown = key;
    render({ level: 'none', label: 'Checking token', score: null });
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: 'oculon:token', chain: t.chain, address: t.address });
    } catch {
      res = null;
    }
    if (shown !== key) return; // the page moved on
    if (!res || res.disabled || res.unsupported) { remove(); return; }
    if (res.error) {
      // 400 means the address is not a token contract on that chain: stay silent. Other errors show softly.
      if (res.status === 400 || res.status === 404) { remove(); return; }
      render({ level: 'none', label: 'Not checked', score: null, title: 'Oculon could not check this token', sub: res.error });
      return;
    }
    const r = res.result;
    const label = { ok: 'No major risks', warn: 'Caution', danger: r.verdict === 'dangerous contract' ? 'Dangerous' : 'Risky' }[r.level] || r.verdict;
    render({ level: r.level, label, score: r.score, title: r.subject, sub: `${r.chain || t.chain} · ${r.verdict}`, reasons: r.reasons, advice: r.advice, report: res.report });
  }

  run();
  setInterval(run, 1000); // these sites are single-page apps: follow URL changes
})();
