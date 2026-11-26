import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const SRC = readFileSync(new URL('../src/web/assets/embed.js', import.meta.url), 'utf8');

interface Helpers {
  sameSite(a: string, b: string): boolean;
  isOutbound(href: string, pageHost: string, allow?: string[]): boolean;
  cacheKey(href: string): string;
  shouldWarn(verdict: string, level: string): boolean;
  parseList(s: string): string[];
  clampMax(s: string): number;
}

/** The script exports its pure helpers when it runs outside a browser, then stops before touching the DOM. */
function helpers(): Helpers {
  const sandbox = { module: { exports: {} as Helpers }, URL };
  vm.runInNewContext(SRC, sandbox, { filename: 'embed.js' });
  return sandbox.module.exports;
}

test('embed: outbound links, same site and the allow list', () => {
  const h = helpers();
  assert.equal(h.isOutbound('https://evil.example/login', 'blog.test'), true);
  assert.equal(h.isOutbound('https://blog.test/post', 'blog.test'), false);
  assert.equal(h.isOutbound('https://www.blog.test/post', 'blog.test'), false);
  assert.equal(h.isOutbound('https://shop.blog.test/', 'blog.test'), false, 'subdomains are the same site');
  assert.equal(h.isOutbound('https://blog.test/', 'app.blog.test'), false);
  assert.equal(h.isOutbound('https://notblog.test/', 'blog.test'), true);
  assert.equal(h.sameSite('notblog.test', 'blog.test'), false, 'a longer name is not a subdomain');
  assert.equal(h.isOutbound('mailto:a@b.test', 'blog.test'), false);
  assert.equal(h.isOutbound('javascript:void(0)', 'blog.test'), false);
  assert.equal(h.isOutbound('https://partner.test/x', 'blog.test', h.parseList(' Partner.test , www.other.test')), false);
  assert.equal(h.isOutbound('https://cdn.partner.test/x', 'blog.test', ['partner.test']), false);
  assert.equal(h.isOutbound('not a url', 'blog.test'), false);
});

test('embed: cache key, warn levels and the per-page budget', () => {
  const h = helpers();
  assert.equal(h.cacheKey('https://a.test/p?q=1#frag'), 'oculon:url:https://a.test/p?q=1');
  assert.equal(h.shouldWarn('malicious', 'suspicious'), true);
  assert.equal(h.shouldWarn('suspicious', 'suspicious'), true);
  assert.equal(h.shouldWarn('suspicious', 'malicious'), false);
  assert.equal(h.shouldWarn('malicious', 'malicious'), true);
  assert.equal(h.shouldWarn('no known threats', 'suspicious'), false);
  assert.equal(h.clampMax(''), 20);
  assert.equal(h.clampMax('5'), 5);
  assert.equal(h.clampMax('999'), 50);
  assert.equal(h.clampMax('-3'), 20);
});

test('embed: no dependencies, storage guarded, key only as a header, no cookies sent', () => {
  assert.doesNotMatch(SRC, /\bimport\s|require\(/);
  assert.ok(SRC.length < 24_000, `small: ${SRC.length} bytes`);
  // Every sessionStorage access sits inside a try block.
  for (const m of SRC.matchAll(/sessionStorage/g)) {
    const before = SRC.slice(Math.max(0, m.index! - 80), m.index);
    assert.match(before, /try \{/, 'sessionStorage outside try');
  }
  assert.match(SRC, /credentials: 'omit'/);
  assert.match(SRC, /if \(key\) init\.headers = \{ authorization: 'Bearer ' \+ key \}/);
  assert.match(SRC, /\/api\/url\?url=' \+ encodeURIComponent/);
  assert.match(SRC, /attachShadow/);
  assert.doesNotMatch(SRC, /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u);
});

test('embed page: both live previews, snippets and the options table', () => {
  const html = readFileSync(new URL('../src/web/embed.html', import.meta.url), 'utf8');
  assert.match(html, /<script src="\/embed\.js" data-oculon-mode="box" async><\/script>/);
  assert.match(html, /data-oculon-mode="links" data-oculon-scope="#demo-links"/);
  assert.match(html, /https:\/\/oculon\.live\/embed\.js/);
  for (const opt of ['mode', 'target', 'warn', 'scope', 'allow', 'max', 'theme', 'key', 'api']) {
    assert.match(html, new RegExp(`data-oculon-${opt}`), opt);
    assert.match(SRC, new RegExp(`opt\\('${opt}'`), `script reads ${opt}`);
  }
  assert.doesNotMatch(html, /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u, 'no emoji');
});
