/** Outgoing email through Resend (RESEND_API_KEY; free tier 3,000 emails a month). Never cached. */
import { key } from '../core/keys.js';

export interface MailResult { ok: boolean; id?: string; error?: string }

export const mailFrom = () => process.env.OCULON_MAIL_FROM?.trim() || 'Oculon <alerts@oculon.live>';
export const mailEnabled = () => Boolean(key('RESEND_API_KEY'));

export async function sendEmail(msg: { to: string; subject: string; html: string; text: string; unsubscribeUrl?: string }, fetchImpl: typeof fetch = fetch): Promise<MailResult> {
  const k = key('RESEND_API_KEY');
  if (!k) return { ok: false, error: 'RESEND_API_KEY is not set' };
  try {
    const res = await fetchImpl('https://api.resend.com/emails', {
      method: 'POST',
      headers: { authorization: `Bearer ${k}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        from: mailFrom(),
        to: [msg.to],
        subject: msg.subject,
        html: msg.html,
        text: msg.text,
        ...(msg.unsubscribeUrl ? { headers: { 'List-Unsubscribe': `<${msg.unsubscribeUrl}>`, 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' } } : {}),
      }),
      signal: AbortSignal.timeout(20_000),
    });
    const j = (await res.json().catch(() => ({}))) as { id?: string; message?: string };
    return res.ok ? { ok: true, id: j.id } : { ok: false, error: `HTTP ${res.status}${j.message ? ` (${j.message})` : ''}` };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}
