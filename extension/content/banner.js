// Shows a small dismissible banner when the service worker marks this site as "be careful".
// It reads nothing from the page; it only asks the service worker what the verdict for this tab is.
(() => {
  if (window.top !== window || window.__oculonBanner) return;
  window.__oculonBanner = true;
  let host = null;

  function show(result) {
    if (host || !result) return;
    host = document.createElement('div');
    host.style.cssText = 'all:initial;position:fixed;top:12px;right:12px;z-index:2147483647';
    const root = host.attachShadow({ mode: 'closed' });
    const reasons = (result.reasons || []).slice(0, 3);
    root.innerHTML = `
      <style>
        .b{box-sizing:border-box;width:340px;max-width:calc(100vw - 24px);background:#05070a;color:#e8e8e8;border:1px solid #f59e0b;border-radius:12px;padding:12px 14px;font:13px/1.45 "Space Grotesk","Segoe UI",system-ui,-apple-system,sans-serif;box-shadow:0 10px 30px rgba(0,0,0,.5)}
        .h{display:flex;align-items:center;gap:8px;font-weight:600;color:#f59e0b;letter-spacing:.02em}
        .m{width:14px;height:14px;flex:none}
        .x{margin-left:auto;background:none;border:0;color:#9aa;font:inherit;font-size:16px;line-height:1;cursor:pointer;padding:2px 4px}
        .x:hover{color:#fff}
        ul{margin:8px 0 0;padding-left:18px;color:#c9c9c9}
        li{margin:2px 0}
        .f{margin-top:8px;font-size:11px;color:#7f8a8f}
      </style>
      <div class="b" role="alert">
        <div class="h">
          <svg class="m" viewBox="212 212 600 600" aria-hidden="true"><path fill="#00f0ff" d="M512 212 H348 Q212 212 212 348 V676 Q212 812 348 812 H676 Q812 812 812 676 V512 H680 V630 Q680 680 630 680 H394 Q344 680 344 630 V394 Q344 344 394 344 H512 Z"/><path fill="#00f0ff" d="M586 212 H676 Q812 212 812 348 V438 Q812 472 778 472 H586 Q552 472 552 438 V246 Q552 212 586 212 Z"/></svg>
          <span>Oculon: be careful on this site</span>
          <button class="x" title="Dismiss" aria-label="Dismiss">&#215;</button>
        </div>
        <ul></ul>
        <div class="f">Risk score ${Number(result.score) || 0}/100. Do not enter passwords, seed phrases or sign wallet requests unless you are sure.</div>
      </div>`;
    const ul = root.querySelector('ul');
    if (!reasons.length) ul.remove();
    for (const r of reasons) {
      const li = document.createElement('li');
      li.textContent = r;
      ul.appendChild(li);
    }
    root.querySelector('.x').addEventListener('click', () => {
      host.remove();
      chrome.runtime.sendMessage({ type: 'oculon:dismissBanner' }).catch(() => {});
    });
    (document.body || document.documentElement).appendChild(host);
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === 'oculon:banner') {
      chrome.runtime.sendMessage({ type: 'oculon:bannerState' }).then((s) => s && show(s.result)).catch(() => {});
    }
  });
  chrome.runtime.sendMessage({ type: 'oculon:bannerState' }).then((s) => s && show(s.result)).catch(() => {});
})();
