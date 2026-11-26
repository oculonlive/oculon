/**
 * Oculon Scam Inbox: a Cloudflare Email Worker for check@<domain>.
 *
 * Email Routing hands every message sent to the inbox address to this Worker. It drops what must not be answered
 * (other addresses, mail over 5 MB, auto-replies, bulk and mailing-list mail, bounces) and posts the raw message to
 * the Oculon server at ${ORIGIN}/api/inbox with the shared secret (INBOX_SECRET, set with
 * `wrangler secret put INBOX_SECRET`, and as OCULON_INBOX_SECRET on the server) and the envelope sender.
 * The server answers at once and sends the verdict back by email itself.
 */
const MAX_BYTES = 5 * 1024 * 1024;

export default {
  async email(message, env, ctx) {
    const allowed = String(env.INBOX_ADDRESS || 'check@oculon.live').toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);
    const to = String(message.to || '').toLowerCase();
    if (!allowed.includes(to)) {
      message.setReject('Unknown address');
      return;
    }
    if (message.rawSize > MAX_BYTES) {
      message.setReject('Message too large: the Oculon inbox takes emails up to 5 MB');
      return;
    }
    const h = message.headers;
    const auto = (h.get('auto-submitted') || '').trim().toLowerCase();
    const precedence = (h.get('precedence') || '').trim().toLowerCase();
    if ((auto && auto !== 'no') || /^(bulk|list|junk|auto_reply)$/.test(precedence) || h.get('list-id') || h.get('x-autoreply') || h.get('x-autorespond')) {
      console.log('inbox: skipped automated or list mail');
      return; // accepted and dropped: no answer, no bounce
    }
    const from = String(message.from || '').trim();
    if (!from || from === '<>' || /^(mailer-daemon|postmaster)@/i.test(from)) return;
    if (!env.ORIGIN || !env.INBOX_SECRET) {
      console.log('inbox: ORIGIN or INBOX_SECRET is not set');
      return;
    }

    // Read the whole message before the handler returns: the stream is gone afterwards.
    const raw = await new Response(message.raw).arrayBuffer();
    const post = fetch(new URL('/api/inbox', env.ORIGIN).href, {
      method: 'POST',
      headers: { 'content-type': 'message/rfc822', 'x-oculon-inbox': env.INBOX_SECRET, 'x-oculon-from': from },
      body: raw,
    })
      .then((res) => { if (!res.ok) console.log(`inbox: server answered ${res.status}`); })
      .catch((e) => console.log(`inbox: server unreachable (${e && e.message})`));
    if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(post);
    else await post;
  },
};
