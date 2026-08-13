import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { GarminClient, KVTokenStorage, MemoryTokenStorage, type KVNamespaceBinding } from './client';
import { createGarminMcpServer } from './server';

export interface Env {
  GARMIN_EMAIL?: string;
  GARMIN_PASSWORD?: string;
  AUTH_TOKEN?: string;
  GARMIN_TOKENS?: KVNamespaceBinding;
}

const memoryStorage = new MemoryTokenStorage();

function corsHeaders(origin?: string | null): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Mcp-Session-Id, Mcp-Protocol-Version, x-api-key',
    'Access-Control-Expose-Headers': 'Mcp-Session-Id',
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin');
    const headers = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    if ((url.pathname === '/' || url.pathname === '/health') && request.method === 'GET' && !request.headers.get('Accept')?.includes('text/event-stream')) {
      return new Response(
        JSON.stringify({
          status: 'ok',
          service: 'garmin-connect-mcp',
          mcpVersion: '1.1.0',
          endpoints: {
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

    if (env.AUTH_TOKEN) {
      const authHeader = request.headers.get('Authorization');
      const apiKeyHeader = request.headers.get('x-api-key');
      const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : null;
      const providedToken = bearerToken || apiKeyHeader;

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

    const email = env.GARMIN_EMAIL;
    const password = env.GARMIN_PASSWORD;

    if (!email || !password) {
      return new Response(
        JSON.stringify({
          error: 'Configuration Error: GARMIN_EMAIL and GARMIN_PASSWORD must be configured as Worker secrets or environment variables.',
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

    const client = new GarminClient(email, password, undefined, tokenStorage);
    const server = createGarminMcpServer(client);

    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: () => crypto.randomUUID(),
    });

    await server.connect(transport);

    const response = await transport.handleRequest(request);

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
