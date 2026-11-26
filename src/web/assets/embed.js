/*! Oculon Embed: link checks for any website. MIT. https://oculon.live/embed
 *
 * <script src="https://oculon.live/embed.js" data-oculon-mode="box" async></script>
 *   box   : a small "Check a link" widget at the script's position, or inside <div id="oculon-check">.
 *   links : outbound links on the page are checked when clicked (and when hovered, ahead of time);
 *           a malicious or suspicious destination gets a warning screen first.
 * Options (data attributes on the script tag):
 *   data-oculon-mode    box | links                          (default box)
 *   data-oculon-target  id of the element the box goes into  (default oculon-check)
 *   data-oculon-warn    suspicious | malicious               which verdicts warn in links mode (default suspicious: both)
 *   data-oculon-scope   CSS selector: only links inside it   (default the whole page)
 *   data-oculon-allow   comma-separated hosts never checked  (your own partners, for example)
 *   data-oculon-max     most checks per page view, 1-50      (default 20)
 *   data-oculon-theme   dark | light                         (default dark)
 *   data-oculon-key     API key, sent as "Authorization: Bearer <key>" (optional, for higher limits later)
 *   data-oculon-api     Oculon server to ask                 (default: where this script was loaded from)
 * A failed or slow check never blocks a link: the visitor goes through as if the script were not there.
 */
(function () {
  'use strict';

  var VERSION = '1';
  var CACHE_MS = 30 * 60 * 1000;
  var CLICK_TIMEOUT_MS = 3500;
  var BOX_TIMEOUT_MS = 12000;

  function hostOf(u) {
    try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ''); } catch (e) { return ''; }
  }
  /** Same site: the same host, or one a subdomain of the other (app.example.com and example.com). */
  function sameSite(a, b) {
    a = String(a || '').toLowerCase().replace(/^www\./, '');
    b = String(b || '').toLowerCase().replace(/^www\./, '');
    if (!a || !b) return false;
    return a === b || a.slice(-(b.length + 1)) === '.' + b || b.slice(-(a.length + 1)) === '.' + a;
  }
  /** An http(s) link that leaves this site and is not on the allow list. */
  function isOutbound(href, pageHost, allow) {
    var u;
    try { u = new URL(href); } catch (e) { return false; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    var h = u.hostname.toLowerCase();
    if (sameSite(h, pageHost)) return false;
    for (var i = 0; i < (allow || []).length; i++) if (allow[i] && sameSite(h, allow[i])) return false;
    return true;
  }
  /** The cache key: the link without its #fragment. */
  function cacheKey(href) {
    try { var u = new URL(href); u.hash = ''; return 'oculon:url:' + u.href; } catch (e) { return 'oculon:url:' + String(href); }
  }
  function shouldWarn(verdict, level) {
    if (verdict === 'malicious') return true;
    return verdict === 'suspicious' && level !== 'malicious';
  }
  function parseList(s) {
    return String(s || '').split(',').map(function (x) { return x.trim().toLowerCase().replace(/^www\./, ''); }).filter(Boolean);
  }
  function clampMax(s) {
    var n = parseInt(s, 10);
    return isFinite(n) && n > 0 ? Math.min(50, n) : 20;
  }

  var helpers = { sameSite: sameSite, isOutbound: isOutbound, cacheKey: cacheKey, shouldWarn: shouldWarn, parseList: parseList, clampMax: clampMax, hostOf: hostOf };
  if (typeof module === 'object' && module && module.exports) module.exports = helpers;
  if (typeof document === 'undefined' || typeof window === 'undefined') return;

  var me = document.currentScript;
  if (!me) {
    var all = document.querySelectorAll('script[src*="embed.js"]');
    for (var k = all.length - 1; k >= 0; k--) if (!all[k].__oculon) { me = all[k]; break; }
  }
  if (!me || me.__oculon) return;
  me.__oculon = true;

  function opt(name, d) { var v = me.getAttribute('data-oculon-' + name); return v == null || v === '' ? d : v; }
  var mode = opt('mode', 'box') === 'links' ? 'links' : 'box';
  var key = opt('key', '');
  var warnLevel = opt('warn', 'suspicious');
  var theme = opt('theme', 'dark') === 'light' ? 'light' : 'dark';
  // The API is where the script came from (so a self-hosted Oculon works too), unless data-oculon-api says otherwise.
  var api = (function () {
    var given = opt('api', '');
    try {
      var u = new URL(given || me.src, location.href);
      if (u.protocol === 'https:' || /^(localhost|127\.0\.0\.1)$/.test(u.hostname)) return u.origin;
    } catch (e) { /* fall through */ }
    return 'https://oculon.live';
  })();
  var home = /(^|\.)oculon\.live$/.test(hostOf(api)) ? 'https://oculon.live' : api;

  // One budget per page view, shared by every Oculon script on the page.
  var G = window.__oculonEmbed = window.__oculonEmbed || { used: 0, max: 0, mem: {}, inflight: {} };
  G.max = Math.max(G.max, clampMax(opt('max', '20')));

  function readCache(href) {
    var k = cacheKey(href);
    var hit = G.mem[k];
    if (!hit) {
      try { var raw = window.sessionStorage.getItem(k); if (raw) hit = JSON.parse(raw); } catch (e) { hit = null; }
    }
    if (hit && Date.now() - hit.at < CACHE_MS) return hit;
    return null;
  }
  function writeCache(href, v) {
    var k = cacheKey(href);
    G.mem[k] = v;
    try { window.sessionStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* storage blocked or full: memory only */ }
  }

  /** One check against /api/url. Resolves to {verdict, risk, reasons, host} or null on any failure. */
  function check(href, timeoutMs) {
    var cached = readCache(href);
    if (cached) return Promise.resolve(cached);
    var k = cacheKey(href);
    if (G.inflight[k]) return G.inflight[k];
    if (G.used >= G.max) return Promise.resolve(null);
    G.used++;
    var ctl = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, timeoutMs);
    var init = { method: 'GET', credentials: 'omit', mode: 'cors', referrerPolicy: 'strict-origin-when-cross-origin' };
    if (ctl) init.signal = ctl.signal;
    if (key) init.headers = { authorization: 'Bearer ' + key };
    var p = fetch(api + '/api/url?url=' + encodeURIComponent(href), init)
      .then(function (res) {
        if (res.status === 429) return { limited: true };
        if (!res.ok) return null;
        return res.json().then(function (j) {
          var r = j && j.result;
          if (!r || typeof r.verdict !== 'string') return null;
          var v = { verdict: r.verdict, risk: Number(r.risk) || 0, reasons: (r.reasons || []).slice(0, 3).map(String), host: String(r.host || hostOf(href)), at: Date.now() };
          writeCache(href, v);
          return v;
        });
      })
      .catch(function () { return null; })
      .then(function (v) { clearTimeout(timer); delete G.inflight[k]; return v; });
    G.inflight[k] = p;
    return p;
  }

  var C = theme === 'light'
    ? { bg: '#ffffff', fg: '#0b1416', mut: '#5b6b6f', line: '#d5dfe1', acc: '#007f8a', field: '#f4f8f9' }
    : { bg: '#05090a', fg: '#f2f6f7', mut: '#9aa7aa', line: '#1f2a2d', acc: '#00f0ff', field: '#000000' };
  var BASE_CSS = ':host{all:initial}*{box-sizing:border-box}'
    + '.w{font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:' + C.fg + ';background:' + C.bg + ';border:1px solid ' + C.line + ';border-radius:10px;padding:14px;max-width:460px;width:100%}'
    + '.t{font-weight:600;font-size:15px;margin:0 0 8px}'
    + 'form{display:flex;gap:6px}input{flex:1;min-width:0;font:13px ui-monospace,Consolas,monospace;padding:9px 10px;border:1px solid ' + C.line + ';border-radius:6px;background:' + C.field + ';color:' + C.fg + '}'
    + 'button{font:600 13px system-ui,sans-serif;padding:9px 12px;border:0;border-radius:6px;background:' + C.acc + ';color:#001418;cursor:pointer}button[disabled]{opacity:.5;cursor:default}'
    + '.r{margin-top:10px}.p{display:inline-block;font:700 11px ui-monospace,monospace;letter-spacing:.06em;padding:3px 7px;border-radius:4px;border:1px solid}'
    + '.bad{color:#ff5d6c;border-color:rgba(255,93,108,.5);background:rgba(255,93,108,.08)}.mid{color:#d9901f;border-color:rgba(255,184,77,.55);background:rgba(255,184,77,.08)}.ok{color:#1fae6f;border-color:rgba(61,220,151,.5);background:rgba(61,220,151,.07)}'
    + '.h{font:12px ui-monospace,monospace;color:' + C.mut + ';margin-left:6px;word-break:break-all}ul{margin:8px 0 0;padding-left:18px}li{margin:2px 0;font-size:13px}'
    + '.m{font-size:12px;color:' + C.mut + ';margin-top:8px}.f{margin-top:10px;font-size:11px;color:' + C.mut + '}.f a{color:' + C.mut + '}';

  function el(tag, attrs, text) {
    var n = document.createElement(tag);
    for (var a in attrs) if (Object.prototype.hasOwnProperty.call(attrs, a)) n.setAttribute(a, attrs[a]);
    if (text != null) n.textContent = text;
    return n;
  }
  function shadowOf(host, css) {
    var root = host.attachShadow ? host.attachShadow({ mode: 'open' }) : host;
    root.appendChild(el('style', {}, css));
    return root;
  }
  function pillFor(v) {
    var cls = v.verdict === 'malicious' ? 'bad' : v.verdict === 'suspicious' ? 'mid' : 'ok';
    return el('span', { class: 'p ' + cls }, v.verdict.toUpperCase());
  }
  function footer() {
    var f = el('div', { class: 'f' }, 'Checked by ');
    f.appendChild(el('a', { href: home, target: '_blank', rel: 'noopener' }, 'Oculon'));
    f.appendChild(document.createTextNode('. A clean result is not a promise that a page is safe.'));
    return f;
  }

  // ------------------------------------------------------------------ box
  function mountBox() {
    var target = document.getElementById(opt('target', 'oculon-check'));
    var host;
    if (target && !target.__oculon) { host = target; }
    else {
      host = el('div', { 'data-oculon': 'box' });
      if (me.parentNode && me.parentNode !== document.head) me.parentNode.insertBefore(host, me.nextSibling);
      else (document.body || document.documentElement).appendChild(host);
    }
    host.__oculon = true;
    var root = shadowOf(host, BASE_CSS);
    var w = el('div', { class: 'w', part: 'widget' });
    w.appendChild(el('div', { class: 't' }, 'Check a link'));
    var form = el('form', { novalidate: '' });
    var input = el('input', { type: 'text', placeholder: 'Paste a link or a domain', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Link to check', maxlength: '2000' });
    var btn = el('button', { type: 'submit' }, 'Check');
    form.appendChild(input); form.appendChild(btn);
    var out = el('div', { class: 'r', 'aria-live': 'polite' });
    w.appendChild(form); w.appendChild(out); w.appendChild(footer());
    root.appendChild(w);
    var last = 0;
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var q = input.value.trim();
      if (!q || btn.disabled) return;
      if (Date.now() - last < 1500) return;
      last = Date.now();
      if (!readCache(q) && G.used >= G.max) { out.textContent = ''; out.appendChild(el('div', { class: 'm' }, 'Check limit for this page reached. Open oculon.live to check more links.')); return; }
      btn.disabled = true;
      out.textContent = '';
      out.appendChild(el('div', { class: 'm' }, 'Checking...'));
      check(q, BOX_TIMEOUT_MS).then(function (v) {
        btn.disabled = false;
        out.textContent = '';
        if (!v) { out.appendChild(el('div', { class: 'm' }, 'The check could not finish. Try again in a moment.')); return; }
        if (v.limited) { out.appendChild(el('div', { class: 'm' }, 'Too many checks right now. Try again in a minute.')); return; }
        var line = el('div', {});
        line.appendChild(pillFor(v));
        line.appendChild(el('span', { class: 'h' }, v.host + ' · risk ' + v.risk + '/100'));
        out.appendChild(line);
        if (v.reasons.length) {
          var ul = el('ul', {});
          v.reasons.forEach(function (r) { ul.appendChild(el('li', {}, r)); });
          out.appendChild(ul);
        }
      });
    });
  }

  // ------------------------------------------------------------------ links
  function mountLinks() {
    if (G.links) return;
    G.links = true;
    var pageHost = location.hostname;
    var allow = parseList(opt('allow', '')).concat([hostOf(api)]);
    var scope = opt('scope', '');
    var overlay = null;

    function linkFrom(t) {
      var a = t && t.closest ? t.closest('a[href]') : null;
      if (!a || a.hasAttribute('data-oculon-skip') || a.hasAttribute('download')) return null;
      if (scope) { try { if (!a.closest(scope)) return null; } catch (e) { return null; } }
      return isOutbound(a.href, pageHost, allow) ? a : null;
    }
    function go(a, href, blankWin) {
      var newTab = blankWin || (a.target && a.target !== '_self' && a.target !== '_top' && a.target !== '_parent');
      if (blankWin && !blankWin.closed) { try { blankWin.location.replace(href); return; } catch (e) { /* fall through */ } }
      if (newTab) {
        // window.open with "noopener" always returns null, so the opener is cut by hand instead.
        var w = window.open(href, '_blank');
        if (w) { try { w.opener = null; } catch (e) { /* ignore */ } return; }
      }
      location.assign(href);
    }
    function closeOverlay() { if (overlay) { overlay.remove(); overlay = null; } }
    function warn(a, href, v) {
      closeOverlay();
      overlay = el('div', { 'data-oculon': 'warning' });
      var root = shadowOf(overlay, BASE_CSS
        + '.o{position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,.72);display:flex;align-items:center;justify-content:center;padding:16px}'
        + '.w{max-width:480px;box-shadow:0 20px 60px rgba(0,0,0,.5)}.t{font-size:18px}.u{font:12px ui-monospace,monospace;color:' + C.mut + ';word-break:break-all;margin:6px 0}'
        + '.b{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.k{background:transparent;color:' + C.mut + ';border:1px solid ' + C.line + '}');
      var o = el('div', { class: 'o', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Link warning' });
      var w = el('div', { class: 'w' });
      w.appendChild(el('div', { class: 't' }, v.verdict === 'malicious' ? 'This link looks dangerous' : 'This link looks suspicious'));
      var line = el('div', {});
      line.appendChild(pillFor(v));
      line.appendChild(el('span', { class: 'h' }, 'risk ' + v.risk + '/100'));
      w.appendChild(line);
      w.appendChild(el('div', { class: 'u' }, href));
      if (v.reasons.length) { var ul = el('ul', {}); v.reasons.forEach(function (r) { ul.appendChild(el('li', {}, r)); }); w.appendChild(ul); }
      var b = el('div', { class: 'b' });
      var back = el('button', { type: 'button' }, 'Go back');
      var on = el('button', { type: 'button', class: 'k' }, 'Continue anyway');
      back.addEventListener('click', closeOverlay);
      on.addEventListener('click', function () { closeOverlay(); go(a, href, null); });
      b.appendChild(back); b.appendChild(on); w.appendChild(b); w.appendChild(footer());
      o.appendChild(w);
      o.addEventListener('click', function (e) { if (e.target === o) closeOverlay(); });
      o.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeOverlay(); });
      root.appendChild(o);
      document.documentElement.appendChild(overlay);
      try { back.focus(); } catch (e) { /* ignore */ }
    }

    document.addEventListener('click', function (e) {
      if (e.defaultPrevented || e.button !== 0) return;
      var a = linkFrom(e.target);
      if (!a) return;
      var href = a.href;
      var cached = readCache(href);
      if (cached) {
        if (shouldWarn(cached.verdict, warnLevel)) { e.preventDefault(); warn(a, href, cached); }
        return;
      }
      // Modifier clicks open a tab the page never sees; check in the background for next time.
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) { check(href, CLICK_TIMEOUT_MS); return; }
      if (G.used >= G.max && !G.inflight[cacheKey(href)]) return; // budget spent: never stand in the way
      e.preventDefault();
      var newTab = a.target && a.target !== '_self' && a.target !== '_top' && a.target !== '_parent';
      // Open the tab now, while the click still counts, so a popup blocker does not eat it after the check.
      var blankWin = null;
      if (newTab) { try { blankWin = window.open('about:blank', '_blank'); if (blankWin) blankWin.opener = null; } catch (err) { blankWin = null; } }
      a.setAttribute('aria-busy', 'true');
      check(href, CLICK_TIMEOUT_MS).then(function (v) {
        a.removeAttribute('aria-busy');
        if (v && !v.limited && shouldWarn(v.verdict, warnLevel)) {
          if (blankWin) { try { blankWin.close(); } catch (err) { /* ignore */ } }
          warn(a, href, v);
          return;
        }
        go(a, href, blankWin);
      });
    }, true);

    // Hovering or focusing a link for a moment checks it ahead of the click, so most clicks are instant.
    var hoverTimer = null;
    function prefetch(e) {
      var a = linkFrom(e.target);
      if (!a || readCache(a.href)) return;
      clearTimeout(hoverTimer);
      hoverTimer = setTimeout(function () { if (G.used < G.max) check(a.href, BOX_TIMEOUT_MS); }, 250);
    }
    document.addEventListener('mouseover', prefetch, { passive: true });
    document.addEventListener('focusin', prefetch);
    document.addEventListener('touchstart', prefetch, { passive: true });
  }

  window.OculonEmbed = window.OculonEmbed || { version: VERSION, check: function (u) { return check(String(u), BOX_TIMEOUT_MS); } };
  function start() { if (mode === 'links') mountLinks(); else mountBox(); }
  if (mode === 'box' && document.readyState === 'loading' && !document.getElementById(opt('target', 'oculon-check'))) document.addEventListener('DOMContentLoaded', start);
  else start();
})();
