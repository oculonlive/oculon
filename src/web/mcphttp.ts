/**
 * Remote MCP over Streamable HTTP (MCP 2025-03-26 and later), stateless.
 * Clients POST JSON-RPC messages (one or a batch) to the endpoint and get JSON back; notifications get 202.
 * There is no server-initiated stream, so GET answers 405 (a browser GET gets a page that explains how to connect).
 * Every tool call goes through the same McpServer the stdio transport uses.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { McpServer } from '../mcp.js';

const CORS: Record<string, string> = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, GET, DELETE, OPTIONS',
  'access-control-allow-headers': 'content-type, accept, authorization, mcp-session-id, mcp-protocol-version, last-event-id',
  'access-control-expose-headers': 'mcp-session-id',
  'access-control-max-age': '86400',
};

const LIMIT = 1_000_000;

function reply(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = body === undefined ? '' : JSON.stringify(body);
  res.writeHead(status, { ...CORS, ...(text ? { 'content-type': 'application/json; charset=utf-8' } : {}), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...extra });
  res.end(text);
}

async function readBody(req: IncomingMessage): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > LIMIT) throw new Error('too large');
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

type Msg = { jsonrpc?: string; id?: number | string | null; method?: string; params?: Record<string, unknown>; result?: unknown; error?: unknown };

/** Answers one HTTP request on the MCP endpoint. `page` renders the HTML a browser GET sees. */
export async function handleMcpHttp(req: IncomingMessage, res: ServerResponse, mcp: McpServer, page: () => Promise<string>, log: (m: string) => void = () => {}, guard?: (tool: string) => Promise<string | null>): Promise<void> {
  if (req.method === 'OPTIONS') return reply(res, 204, undefined);
  if (req.method === 'GET' || req.method === 'HEAD') {
    if (/text\/html/.test(String(req.headers.accept ?? ''))) {
      const html = await page();
      res.writeHead(200, { ...CORS, 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache', 'x-content-type-options': 'nosniff' });
      return void res.end(req.method === 'HEAD' ? undefined : html);
    }
    return reply(res, 405, { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'This server does not open a GET stream; POST JSON-RPC messages to this URL.' } }, { allow: 'POST, OPTIONS' });
  }
  if (req.method === 'DELETE') return reply(res, 405, undefined, { allow: 'POST, OPTIONS' });
  if (req.method !== 'POST') return reply(res, 405, undefined, { allow: 'POST, OPTIONS' });

  let parsed: unknown;
  try {
    parsed = JSON.parse(await readBody(req));
  } catch (e) {
    const tooLarge = (e as Error).message === 'too large';
    return reply(res, tooLarge ? 413 : 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: tooLarge ? 'request too large' : 'parse error' } });
  }
  const batch = Array.isArray(parsed);
  const messages = (batch ? parsed : [parsed]) as Msg[];
  if (!messages.length || messages.some((m) => !m || typeof m !== 'object')) return reply(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'invalid request' } });

  const out: unknown[] = [];
  for (const m of messages) {
    // Responses and notifications from the client need no answer.
    if (!m.method) continue;
    // A tool call may be refused by the API key gate (tier or daily quota); the client sees it as a tool error.
    const refused = guard && m.method === 'tools/call' ? await guard(String(m.params?.name ?? '')) : null;
    const r = refused ? { jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: refused }], isError: true } } : await mcp.handle({ jsonrpc: '2.0', id: m.id, method: m.method, params: m.params });
    if (m.method === 'tools/call') log(`mcp ${String(m.params?.name ?? '')}`);
    if (r && m.id !== undefined && m.id !== null) out.push(r);
  }
  if (!out.length) return reply(res, 202, undefined);
  return reply(res, 200, batch ? out : out[0]);
}
