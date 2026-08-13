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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin');
    const headers = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

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

    const authHeader = request.headers.get('Authorization');
    const apiKeyHeader = request.headers.get('x-api-key');
    const queryToken = url.searchParams.get('token') || url.searchParams.get('auth_token');
    const basicAuth = parseBasicAuth(authHeader);

    if (env.AUTH_TOKEN) {
      const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : null;
      const providedToken = bearerToken || apiKeyHeader || queryToken || basicAuth?.password || basicAuth?.username;

      if (!providedToken || providedToken !== env.AUTH_TOKEN) {
        return new Response(
          JSON.stringify({ error: 'Unauthorized: Invalid or missing authentication token' }),
          {
            status: 401,
            headers: { ...headers, 'Content-Type': 'application/json' },
          },
        );
      }
    }

    let email = env.GARMIN_EMAIL;
    let password = env.GARMIN_PASSWORD;

    if (basicAuth?.username && basicAuth?.password) {
      email = basicAuth.username;
      password = basicAuth.password;
    }

    if (!email || !password) {
      return new Response(
        JSON.stringify({
          error: 'Configuration Error: GARMIN_EMAIL and GARMIN_PASSWORD must be configured as Worker secrets or provided via Basic Auth credentials.',
        }),
        {
          status: 500,
          headers: { ...headers, 'Content-Type': 'application/json' },
        },
      );
    }

    const tokenStorage = env.GARMIN_TOKENS
      ? new KVTokenStorage(env.GARMIN_TOKENS)
      : memoryStorage;

    const acceptHeader = request.headers.get('Accept') || '';
    const isSseGet = request.method === 'GET' && (
      url.pathname === '/sse' ||
      acceptHeader.includes('text/event-stream')
    );

    if (isSseGet) {
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
      const client = new GarminClient(email, password, undefined, tokenStorage);
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

    // Direct JSON-RPC POST (Streamable HTTP / Gemini / Cursor)
    const normalizedHeaders = new Headers(request.headers);
    if (!normalizedHeaders.get('Accept')?.includes('application/json') || !normalizedHeaders.get('Accept')?.includes('text/event-stream')) {
      normalizedHeaders.set('Accept', 'application/json, text/event-stream');
    }

    const client = new GarminClient(email, password, undefined, tokenStorage);
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
