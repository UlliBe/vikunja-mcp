#!/usr/bin/env node

/**
 * Vikunja MCP Server — Streamable HTTP transport.
 *
 * Added in this fork. Upstream ships stdio only (src/index.ts), which would put
 * the Vikunja API token in the MCP client's config on every machine that wants
 * access. Running the server here instead keeps that token on the host: clients
 * authenticate to *this* process with a separate, independently revocable
 * bearer token, and never see the Vikunja credential.
 *
 * Deliberately self-contained rather than importing src/index.ts: that module
 * builds a singleton McpServer and connects stdio as a side effect of being
 * imported. Duplicating ~30 lines of setup is cheaper than making the stdio
 * entry point conditional and risking a regression in it.
 *
 * Environment:
 *   VIKUNJA_URL        Vikunja API base, e.g. http://vikunja:3456/api/v1
 *   VIKUNJA_API_TOKEN  Vikunja API token (tk_...) — stays on the server
 *   MCP_AUTH_TOKEN     bearer token clients must present (required)
 *   MCP_HOST           bind address (default 127.0.0.1 — never 0.0.0.0 by default)
 *   MCP_PORT           bind port (default 3100)
 *   MCP_ALLOWED_HOSTS  comma-separated Host allow-list for DNS-rebinding protection
 *   MCP_ALLOW_DELETE   set to "true" to lift the delete block (default: blocked)
 */

import { randomUUID, createHash, timingSafeEqual } from 'node:crypto';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import express, { type Request, type Response, type NextFunction } from 'express';
import dotenv from 'dotenv';

import { AuthManager } from './auth/AuthManager';
import { registerTools } from './tools';
import { logger } from './utils/logger';
import { createVikunjaClientFactory, setGlobalClientFactory, type VikunjaClientFactory } from './client';

dotenv.config({ quiet: true });

const PORT = Number(process.env.MCP_PORT ?? 3100);
// Default to loopback, not 0.0.0.0: a wrong/missing env var should fail closed
// (unreachable) rather than silently publish this on every interface.
const HOST = process.env.MCP_HOST ?? '127.0.0.1';
const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN ?? '';
const ALLOW_DELETE = process.env.MCP_ALLOW_DELETE === 'true';
const ALLOWED_HOSTS = (process.env.MCP_ALLOWED_HOSTS ?? '')
  .split(',')
  .map((h) => h.trim())
  .filter(Boolean);

if (!AUTH_TOKEN) {
  // Refuse to start rather than expose an unauthenticated write-capable bridge
  // to the Vikunja API. There is no "no auth" mode on purpose.
  logger.error('MCP_AUTH_TOKEN is not set — refusing to start.');
  process.exit(1);
}

/**
 * Constant-time bearer comparison.
 *
 * timingSafeEqual throws on length mismatch, and the length itself leaks, so
 * both sides are hashed to a fixed 32 bytes first.
 */
const AUTH_DIGEST = createHash('sha256').update(AUTH_TOKEN).digest();
function bearerOk(header: string | undefined): boolean {
  if (!header?.startsWith('Bearer ')) return false;
  const presented = createHash('sha256').update(header.slice(7)).digest();
  return timingSafeEqual(AUTH_DIGEST, presented);
}

/**
 * Destructive-operation gate.
 *
 * Second layer only — the Vikunja API token itself is issued without delete
 * grants, and returns 401 on any delete route. This exists so a bug or an
 * upstream change in the tool layer cannot quietly turn deletion back on.
 *
 * `remove-*` subcommands (remove-label, remove-reminder, ...) are NOT blocked:
 * they unset a relation and are reversible. Only `*delete*` subcommands, which
 * destroy an entity, are refused. Vikunja has no trash and no undo.
 */
/**
 * Tools do not agree on what to call their operation field. An audit of every
 * `z.enum` discriminator in src/tools found three distinct keys carrying
 * delete values, spread across different tools:
 *
 *   subcommand  -> delete, bulk-delete, delete-share   (vikunja_tasks, ...)
 *   operation   -> delete, bulk-delete                 (vikunja_task_crud, vikunja_task_bulk)
 *   action      -> delete                              (vikunja_filters)
 *
 * Checking only `subcommand` — as the first version of this gate did — leaves
 * vikunja_task_crud and vikunja_task_bulk completely ungated, which is exactly
 * the pair that deletes tasks. `memberSubcommand` is included defensively: it
 * is a discriminator today with no delete value, and adding it costs nothing.
 *
 * Matching is restricted to these keys rather than scanning all argument values
 * so that free text — a task titled "delete the old server" — is not refused.
 */
const OPERATION_KEYS = ['subcommand', 'operation', 'action', 'memberSubcommand'] as const;

function isBlockedDelete(body: unknown): string | null {
  if (ALLOW_DELETE || !body) return null;
  const calls = Array.isArray(body) ? body : [body];
  for (const call of calls) {
    const c = call as { method?: string; params?: { name?: string; arguments?: Record<string, unknown> } };
    if (c?.method !== 'tools/call') continue;
    const args = c.params?.arguments;
    if (!args) continue;
    for (const key of OPERATION_KEYS) {
      const value = args[key];
      if (typeof value === 'string' && value.toLowerCase().includes('delete')) {
        return `${c.params?.name ?? 'tool'}/${key}=${value}`;
      }
    }
  }
  return null;
}

// Shared across sessions: auth + client factory are stateless w.r.t. the MCP
// session, only the McpServer instance is per-session (an McpServer binds to a
// single transport, so sessions cannot share one).
const authManager = new AuthManager();
let clientFactory: VikunjaClientFactory | null = null;

async function initShared(): Promise<void> {
  if (process.env.VIKUNJA_URL && process.env.VIKUNJA_API_TOKEN) {
    authManager.connect(process.env.VIKUNJA_URL, process.env.VIKUNJA_API_TOKEN);
    logger.info(`Auto-authenticated (auth type: ${authManager.getAuthType()})`);
  } else {
    logger.warn('VIKUNJA_URL / VIKUNJA_API_TOKEN not set — tools will report unauthenticated.');
  }
  try {
    clientFactory = await createVikunjaClientFactory(authManager);
    if (clientFactory) await setGlobalClientFactory(clientFactory);
  } catch (error) {
    logger.warn('Client factory init failed; will retry per session:', error);
  }
}

function buildServer(): McpServer {
  const server = new McpServer({ name: 'vikunja-mcp', version: '0.2.2-htz' });
  registerTools(server, authManager, clientFactory ?? undefined);
  return server;
}

const transports = new Map<string, StreamableHTTPServerTransport>();
const lastSeen = new Map<string, number>();

// The process runs under `restart: unless-stopped` and so effectively never
// restarts. Sessions are only removed on an explicit close, so a client that
// opens sessions without tearing them down would grow this map for the life of
// the container. Both bounds below are deliberately generous — they are a
// backstop against leaked sessions, not a usage limit.
const MAX_SESSIONS = 64;
const SESSION_IDLE_MS = 60 * 60 * 1000;

function reapSessions(): void {
  const cutoff = Date.now() - SESSION_IDLE_MS;
  for (const [id, seen] of lastSeen) {
    if (seen < cutoff) {
      transports.get(id)?.close();
      transports.delete(id);
      lastSeen.delete(id);
      logger.info(`Reaped idle MCP session: ${id}`);
    }
  }
  // Still over the cap after reaping idle ones: drop the oldest.
  while (transports.size > MAX_SESSIONS) {
    const oldest = [...lastSeen.entries()].sort((a, b) => a[1] - b[1])[0]?.[0];
    if (!oldest) break;
    transports.get(oldest)?.close();
    transports.delete(oldest);
    lastSeen.delete(oldest);
    logger.warn(`Evicted oldest MCP session (cap ${MAX_SESSIONS}): ${oldest}`);
  }
}

async function main(): Promise<void> {
  await initShared();

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '4mb' }));

  // Unauthenticated on purpose: it exposes no Vikunja data and is scraped by
  // Prometheus, which does not carry the bearer token.
  app.get('/health', (_req: Request, res: Response) => {
    res.json({
      status: 'ok',
      authenticated: authManager.getAuthType() !== undefined,
      sessions: transports.size,
      deleteBlocked: !ALLOW_DELETE,
    });
  });

  app.use('/mcp', (req: Request, res: Response, next: NextFunction) => {
    if (!bearerOk(req.headers.authorization)) {
      logger.warn(`Rejected unauthenticated MCP request from ${req.ip}`);
      res.status(401).json({
        jsonrpc: '2.0',
        error: { code: -32001, message: 'Unauthorized' },
        id: null,
      });
      return;
    }
    const blocked = isBlockedDelete(req.body);
    if (blocked) {
      logger.warn(`Blocked destructive call: ${blocked}`);
      res.status(403).json({
        jsonrpc: '2.0',
        error: {
          code: -32002,
          message:
            `Refused: '${blocked}' is a delete operation. This server is deployed read/write ` +
            `without delete, and the Vikunja token has no delete grants either. Vikunja has no ` +
            `trash — delete from the web UI if you really mean it.`,
        },
        id: (req.body as { id?: unknown })?.id ?? null,
      });
      return;
    }
    next();
  });

  app.post('/mcp', async (req: Request, res: Response) => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    let transport = sessionId ? transports.get(sessionId) : undefined;

    // Only an initialize request may create a session. Without this check, a
    // client still sending a session id from before a restart (the map is
    // in-memory) would make us build a fresh McpServer — dozens of zod tool
    // registrations — on every request, only for the transport's own
    // validateSession() to reject it moments later. Fail fast instead.
    if (!transport && !isInitializeRequest(req.body)) {
      res.status(400).json({
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'No valid session. Send an initialize request first.',
        },
        id: (req.body as { id?: unknown })?.id ?? null,
      });
      return;
    }

    if (!transport) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        enableDnsRebindingProtection: ALLOWED_HOSTS.length > 0,
        ...(ALLOWED_HOSTS.length > 0 ? { allowedHosts: ALLOWED_HOSTS } : {}),
        onsessioninitialized: (id: string) => {
          transports.set(id, transport as StreamableHTTPServerTransport);
          lastSeen.set(id, Date.now());
          logger.info(`MCP session opened: ${id}`);
          reapSessions();
        },
      });
      transport.onclose = (): void => {
        if (transport?.sessionId) {
          transports.delete(transport.sessionId);
          lastSeen.delete(transport.sessionId);
          logger.info(`MCP session closed: ${transport.sessionId}`);
        }
      };
      await buildServer().connect(transport);
    } else if (sessionId) {
      lastSeen.set(sessionId, Date.now());
    }
    await transport.handleRequest(req, res, req.body);
  });

  // GET = server->client SSE stream, DELETE = MCP session teardown. Neither is
  // a Vikunja delete; the gate above only inspects tools/call bodies.
  const bySession = async (req: Request, res: Response): Promise<void> => {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    const transport = sessionId ? transports.get(sessionId) : undefined;
    if (!transport) {
      res.status(400).json({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Unknown or missing session id' },
        id: null,
      });
      return;
    }
    await transport.handleRequest(req, res);
  };
  app.get('/mcp', bySession);
  app.delete('/mcp', bySession);

  app.listen(PORT, HOST, () => {
    logger.info(`Vikunja MCP (streamable http) listening on ${HOST}:${PORT}`);
    logger.info(`  delete operations: ${ALLOW_DELETE ? 'ALLOWED' : 'blocked'}`);
    logger.info(`  dns-rebinding protection: ${ALLOWED_HOSTS.length > 0 ? ALLOWED_HOSTS.join(', ') : 'off'}`);
  });
}

main().catch((error) => {
  logger.error('Failed to start HTTP MCP server:', error);
  process.exit(1);
});
