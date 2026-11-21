/**
 * Oculon edge Worker: serves app.<domain>, docs.<domain> and mcp.<domain> (remote MCP) from the same Oculon server.
 *
 * The hosting plan gives the server one custom domain, so this Worker answers the two subdomains and
 * forwards each request to ORIGIN with the site name ("app" or "docs") and the visitor's address in
 * headers. The server trusts those headers only when they carry EDGE_SECRET (set with
 * `wrangler secret put EDGE_SECRET`, and as OCULON_EDGE_SECRET on the server).
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const site = url.hostname.split('.')[0];
    if (site !== 'app' && site !== 'docs' && site !== 'mcp') return new Response('Not found', { status: 404 });

    const target = new URL(url.pathname + url.search, env.ORIGIN);
    const headers = new Headers(request.headers);
    headers.set('x-oculon-site', site);
    headers.set('x-oculon-edge', env.EDGE_SECRET);
    headers.set('x-oculon-client-ip', request.headers.get('cf-connecting-ip') ?? '');
    headers.delete('host');

    // Redirects stay as the server wrote them; streaming responses (the live signal stream) pass through.
    return fetch(target, {
      method: request.method,
      headers,
      body: request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body,
      redirect: 'manual',
    });
  },
};
