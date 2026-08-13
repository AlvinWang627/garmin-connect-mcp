import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { GarminClient, KVTokenStorage, MemoryTokenStorage, type KVNamespaceBinding } from './client';
import { createGarminMcpServer } from './server';

export interface Env {
  GARMIN_EMAIL?: string;
  GARMIN_PASSWORD?: string;
  AUTH_TOKEN?: string;
  GARMIN_TOKENS?: KVNamespaceBinding;
}

export class WebStandardSSETransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  constructor(
    private controller: ReadableStreamDefaultController,
    private encoder: TextEncoder,
  ) {}

  async start(): Promise<void> {}

  async send(message: JSONRPCMessage): Promise<void> {
    const text = `event: message\ndata: ${JSON.stringify(message)}\n\n`;
    try {
      this.controller.enqueue(this.encoder.encode(text));
    } catch (e) {
      this.onerror?.(e instanceof Error ? e : new Error(String(e)));
    }
  }

  async close(): Promise<void> {
    try {
      this.controller.close();
    } catch {}
    this.onclose?.();
  }

  handleMessage(message: JSONRPCMessage): void {
    this.onmessage?.(message);
  }
}

type SessionRecord = {
  sessionId: string;
  transport: WebStandardSSETransport;
  controller: ReadableStreamDefaultController;
};

const activeSessions = new Map<string, SessionRecord>();
const memoryStorage = new MemoryTokenStorage();

function corsHeaders(origin?: string | null): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Mcp-Session-Id, Mcp-Protocol-Version, x-api-key',
    'Access-Control-Expose-Headers': 'Mcp-Session-Id',
  };
}

function parseBasicAuth(authHeader: string | null): { username?: string; password?: string } | null {
  if (!authHeader || !authHeader.startsWith('Basic ')) return null;
  try {
    const base64 = authHeader.substring(6).trim();
    const decoded = atob(base64);
    const index = decoded.indexOf(':');
    if (index === -1) return { username: decoded, password: '' };
    return {
      username: decoded.substring(0, index),
      password: decoded.substring(index + 1),
    };
  } catch {
    return null;
  }
}

function decodeOAuthBearerToken(bearerToken: string): { email: string; password: string } | null {
  try {
    const decoded = atob(bearerToken);
    const idx = decoded.indexOf(':');
    if (idx > 0 && idx < decoded.length - 1) {
      return { email: decoded.substring(0, idx), password: decoded.substring(idx + 1) };
    }
  } catch {}
  return null;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin');
    const headers = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    // ─── Health ───
    if (url.pathname === '/health') {
      return new Response(
        JSON.stringify({
          status: 'ok',
          service: 'garmin-connect-mcp',
          mcpVersion: '1.1.0',
          endpoints: {
            sse: `${url.origin}/sse`,
            message: `${url.origin}/message`,
            mcp: url.origin,
            health: `${url.origin}/health`,
          },
        }),
        {
          status: 200,
          headers: { ...headers, 'Content-Type': 'application/json' },
        },
      );
    }

    // ─── OAuth 2.0 Endpoints (Gemini Spark: Client ID = Garmin Email, Client Secret = Garmin Password) ───

    // Protected Resource Metadata (RFC 9728)
    if (url.pathname === '/.well-known/oauth-protected-resource') {
      return new Response(
        JSON.stringify({
          resource: url.origin,
          authorization_servers: [url.origin],
        }),
        { status: 200, headers: { ...headers, 'Content-Type': 'application/json' } },
      );
    }

    // Authorization Server Metadata (RFC 8414)
    if (url.pathname === '/.well-known/oauth-authorization-server') {
      return new Response(
        JSON.stringify({
          issuer: url.origin,
          authorization_endpoint: `${url.origin}/oauth/authorize`,
          token_endpoint: `${url.origin}/oauth/token`,
          registration_endpoint: `${url.origin}/oauth/register`,
          token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
          grant_types_supported: ['authorization_code', 'client_credentials'],
          response_types_supported: ['code'],
          code_challenge_methods_supported: ['S256'],
        }),
        { status: 200, headers: { ...headers, 'Content-Type': 'application/json' } },
      );
    }

    // Dynamic Client Registration (RFC 7591)
    if (request.method === 'POST' && url.pathname === '/oauth/register') {
      let body: Record<string, unknown> = {};
      try {
        body = (await request.json()) as Record<string, unknown>;
      } catch {}
      return new Response(
        JSON.stringify({
          client_id: crypto.randomUUID(),
          client_secret: '',
          client_name: (body.client_name as string) || 'mcp-client',
          grant_types: ['authorization_code', 'client_credentials'],
          token_endpoint_auth_method: 'client_secret_post',
          redirect_uris: body.redirect_uris || [],
        }),
        { status: 201, headers: { ...headers, 'Content-Type': 'application/json' } },
      );
    }

    // Authorization Endpoint — immediately redirects back with an auth code
    if (url.pathname === '/oauth/authorize') {
      const clientId = url.searchParams.get('client_id') || '';
      const redirectUri = url.searchParams.get('redirect_uri');
      const state = url.searchParams.get('state') || '';
      const codeChallenge = url.searchParams.get('code_challenge') || '';

      if (!redirectUri) {
        return new Response(
          JSON.stringify({ error: 'invalid_request', error_description: 'redirect_uri is required' }),
          { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } },
        );
      }

      // Self-contained auth code: encodes client_id + timestamp + code_challenge
      const codePayload = JSON.stringify({ cid: clientId, ts: Date.now(), cc: codeChallenge });
      const code = btoa(codePayload);

      const redirectUrl = new URL(redirectUri);
      redirectUrl.searchParams.set('code', code);
      if (state) redirectUrl.searchParams.set('state', state);

      return new Response(null, {
        status: 302,
        headers: { ...headers, Location: redirectUrl.toString() },
      });
    }

    // Token Endpoint — exchanges auth code or client credentials for an access token
    if (request.method === 'POST' && url.pathname === '/oauth/token') {
      const contentType = request.headers.get('Content-Type') || '';
      let params: Record<string, string> = {};

      try {
        if (contentType.includes('application/x-www-form-urlencoded')) {
          const body = await request.text();
          for (const [k, v] of new URLSearchParams(body)) params[k] = v;
        } else if (contentType.includes('application/json')) {
          params = (await request.json()) as Record<string, string>;
        }
      } catch {}

      // Client credentials from Basic Auth header or body
      const tokenBasicAuth = parseBasicAuth(request.headers.get('Authorization'));
      const clientId = params.client_id || tokenBasicAuth?.username || '';
      const clientSecret = params.client_secret || tokenBasicAuth?.password || '';
      const grantType = params.grant_type || '';

      if (grantType === 'authorization_code') {
        const code = params.code || '';
        try {
          const codePayload = JSON.parse(atob(code)) as { cid: string; ts: number; cc: string };

          // Verify code is recent (10 minute window)
          if (Date.now() - codePayload.ts > 10 * 60 * 1000) {
            return new Response(
              JSON.stringify({ error: 'invalid_grant', error_description: 'Authorization code expired' }),
              { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } },
            );
          }

          // PKCE verification (RFC 7636)
          if (params.code_verifier && codePayload.cc) {
            const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(params.code_verifier));
            const computed = btoa(String.fromCharCode(...new Uint8Array(digest)))
              .replace(/\+/g, '-')
              .replace(/\//g, '_')
              .replace(/=+$/, '');
            if (computed !== codePayload.cc) {
              return new Response(
                JSON.stringify({ error: 'invalid_grant', error_description: 'PKCE verification failed' }),
                { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } },
              );
            }
          }
        } catch {
          return new Response(
            JSON.stringify({ error: 'invalid_grant', error_description: 'Invalid authorization code' }),
            { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } },
          );
        }
      } else if (grantType !== 'client_credentials') {
        return new Response(
          JSON.stringify({ error: 'unsupported_grant_type' }),
          { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } },
        );
      }

      if (!clientId || !clientSecret) {
        return new Response(
          JSON.stringify({
            error: 'invalid_client',
            error_description: 'Client ID (= your Garmin email) and Client Secret (= your Garmin password) are required.',
          }),
          { status: 401, headers: { ...headers, 'Content-Type': 'application/json' } },
        );
      }

      // Access token encodes the Garmin credentials (stateless — Cloudflare Worker has no persistent memory)
      const accessToken = btoa(`${clientId}:${clientSecret}`);

      return new Response(
        JSON.stringify({
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 86400,
        }),
        {
          status: 200,
          headers: { ...headers, 'Content-Type': 'application/json', 'Cache-Control': 'no-store', Pragma: 'no-cache' },
        },
      );
    }

    // ─── Credential Extraction ───

    const authHeader = request.headers.get('Authorization');
    const apiKeyHeader = request.headers.get('x-api-key');
    const queryToken = url.searchParams.get('token') || url.searchParams.get('auth_token');
    const basicAuth = parseBasicAuth(authHeader);

    let email = env.GARMIN_EMAIL;
    let password = env.GARMIN_PASSWORD;

    // Decode OAuth Bearer token → Garmin credentials
    const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : null;
    if (bearerToken) {
      const oauthCreds = decodeOAuthBearerToken(bearerToken);
      if (oauthCreds) {
        email = oauthCreds.email;
        password = oauthCreds.password;
      }
    }

    // Basic Auth overrides
    if (basicAuth?.username && basicAuth?.password) {
      email = basicAuth.username;
      password = basicAuth.password;
    }

    // ─── AUTH_TOKEN Access Control ───

    if (env.AUTH_TOKEN) {
      // Allow through if credentials came from OAuth Bearer or Basic Auth
      const isOAuthBearer = bearerToken ? !!decodeOAuthBearerToken(bearerToken) : false;
      const isBasicAuth = !!(basicAuth?.username && basicAuth?.password);

      if (!isOAuthBearer && !isBasicAuth) {
        const providedToken = bearerToken || apiKeyHeader || queryToken;
        if (!providedToken || providedToken !== env.AUTH_TOKEN) {
          return new Response(
            JSON.stringify({ error: 'Unauthorized: Invalid or missing authentication token' }),
            { status: 401, headers: { ...headers, 'Content-Type': 'application/json' } },
          );
        }
      }
    }

    const hasCredentials = !!(email && password);

    const tokenStorage = env.GARMIN_TOKENS
      ? new KVTokenStorage(env.GARMIN_TOKENS)
      : memoryStorage;

    // ─── Legacy SSE (Claude Desktop, etc.) — only at /sse ───

    const isSseGet = request.method === 'GET' && url.pathname === '/sse';

    if (isSseGet) {
      if (!hasCredentials) {
        return new Response(
          JSON.stringify({
            error: 'Configuration Error: GARMIN_EMAIL and GARMIN_PASSWORD must be configured as Worker secrets or provided via Basic Auth credentials.',
          }),
          { status: 500, headers: { ...headers, 'Content-Type': 'application/json' } },
        );
      }

      const sessionId = crypto.randomUUID();
      const encoder = new TextEncoder();

      let streamController!: ReadableStreamDefaultController;
      const readable = new ReadableStream({
        start(controller) {
          streamController = controller;
        },
        cancel() {
          activeSessions.delete(sessionId);
        },
      });

      const transport = new WebStandardSSETransport(streamController, encoder);
      const client = new GarminClient(email!, password!, undefined, tokenStorage);
      const server = createGarminMcpServer(client);

      await server.connect(transport);

      activeSessions.set(sessionId, { sessionId, transport, controller: streamController });

      const targetPath = `/message?sessionId=${sessionId}`;
      const endpointEvent = `event: endpoint\ndata: ${targetPath}\n\n`;
      streamController.enqueue(encoder.encode(endpointEvent));

      return new Response(readable, {
        status: 200,
        headers: {
          ...headers,
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache, no-transform',
          Connection: 'keep-alive',
        },
      });
    }

    // ─── Legacy SSE Message (for /sse sessions) ───

    if (request.method === 'POST' && url.pathname === '/message') {
      const sessionId = url.searchParams.get('sessionId');
      if (!sessionId) {
        return new Response(
          JSON.stringify({ error: 'Missing sessionId query parameter' }),
          { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } },
        );
      }

      const session = activeSessions.get(sessionId);
      if (!session) {
        return new Response(
          JSON.stringify({ error: 'Session not found or expired' }),
          { status: 404, headers: { ...headers, 'Content-Type': 'application/json' } },
        );
      }

      try {
        const message = (await request.json()) as JSONRPCMessage;
        session.transport.handleMessage(message);
        return new Response('Accepted', { status: 202, headers });
      } catch (e) {
        return new Response(
          JSON.stringify({ error: 'Invalid JSON payload' }),
          { status: 400, headers: { ...headers, 'Content-Type': 'application/json' } },
        );
      }
    }

    // ─── StreamableHTTP: Gemini Spark, Cursor, and other modern MCP clients ───

    if (request.method !== 'POST') {
      // GET / returns server info (useful for connection probes)
      if (request.method === 'GET') {
        return new Response(
          JSON.stringify({
            name: 'garmin-connect-mcp',
            version: '1.1.0',
            protocol: 'MCP',
            protocolVersion: '2024-11-05',
            transport: 'StreamableHTTP',
            status: hasCredentials ? 'ready' : 'missing_credentials',
          }),
          { status: 200, headers: { ...headers, 'Content-Type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({ error: 'Method not allowed' }),
        { status: 405, headers: { ...headers, 'Content-Type': 'application/json', Allow: 'GET, POST, OPTIONS' } },
      );
    }

    // Normalize Accept header — MCP SDK requires both application/json and text/event-stream
    const normalizedHeaders = new Headers(request.headers);
    const currentAccept = normalizedHeaders.get('Accept') || '';
    if (!currentAccept.includes('application/json') || !currentAccept.includes('text/event-stream')) {
      normalizedHeaders.set('Accept', 'application/json, text/event-stream');
    }

    // Create GarminClient — auth is lazy; initialize and tools/list work without credentials,
    // tool calls will fail with a clear error if credentials are missing
    const client = new GarminClient(email || '', password || '', undefined, tokenStorage);
    const server = createGarminMcpServer(client);

    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // Stateless mode for direct JSON-RPC HTTP requests
      enableJsonResponse: true,
    });

    await server.connect(transport);

    const normalizedReq = new Request(request.url, {
      method: request.method,
      headers: normalizedHeaders,
      body: request.body,
      // @ts-ignore
      duplex: 'half',
    });

    const response = await transport.handleRequest(normalizedReq);

    const responseHeaders = new Headers(response.headers);
    for (const [key, value] of Object.entries(headers)) {
      if (!responseHeaders.has(key)) {
        responseHeaders.set(key, value);
      }
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });
  },
};
