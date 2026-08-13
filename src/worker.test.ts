import { describe, it, expect } from 'vitest';
import worker from './worker';

describe('Worker Handler', () => {
  it('returns 204 for OPTIONS preflight request', async () => {
    const req = new Request('http://localhost/', { method: 'OPTIONS' });
    const res = await worker.fetch(req, {});

    expect(res.status).toBe(204);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
  });

  it('returns health check info for GET /health', async () => {
    const req = new Request('http://localhost/health', { method: 'GET' });
    const res = await worker.fetch(req, {});

    expect(res.status).toBe(200);
    const body = await res.json() as { status: string; service: string };
    expect(body.status).toBe('ok');
    expect(body.service).toBe('garmin-connect-mcp');
  });

  it('handles POST initialize without credentials (MCP handshake works without Garmin auth)', async () => {
    const initPayload = {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'Gemini', version: '1.0' },
      },
    };

    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(initPayload),
    });

    const res = await worker.fetch(req, {});

    expect(res.status).toBe(200);
    const body = await res.json() as { result?: { serverInfo?: { name: string } } };
    expect(body.result?.serverInfo?.name).toBe('garmin-connect-mcp');
  });

  it('supports Basic Auth extraction for Gemini Client ID & Secret', async () => {
    const initPayload = {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'Gemini', version: '1.0' },
      },
    };

    const basicAuthHeader = 'Basic ' + Buffer.from('w28103566@gmail.com:mypassword').toString('base64');
    const req = new Request('http://localhost/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: basicAuthHeader,
      },
      body: JSON.stringify(initPayload),
    });

    const res = await worker.fetch(req, {});

    expect(res.status).toBe(200);
    const body = await res.json() as { result?: { serverInfo?: { name: string } } };
    expect(body.result?.serverInfo?.name).toBe('garmin-connect-mcp');
  });

  it('establishes Classic SSE connection on GET /sse', async () => {
    const req = new Request('http://localhost/sse', { method: 'GET' });
    const env = { GARMIN_EMAIL: 'test@example.com', GARMIN_PASSWORD: 'pass' };
    const res = await worker.fetch(req, env);

    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toBe('text/event-stream');

    const reader = res.body?.getReader();
    const { value } = await reader!.read();
    const text = new TextDecoder().decode(value);
    expect(text).toContain('event: endpoint');
    expect(text).toContain('data: /message?sessionId=');
  });

  it('returns server info for GET /', async () => {
    const req = new Request('http://localhost/', { method: 'GET' });
    const res = await worker.fetch(req, {});

    expect(res.status).toBe(200);
    const body = await res.json() as { name: string; protocol: string };
    expect(body.name).toBe('garmin-connect-mcp');
    expect(body.protocol).toBe('MCP');
  });

  it('returns 500 for GET /sse without credentials', async () => {
    const req = new Request('http://localhost/sse', { method: 'GET' });
    const res = await worker.fetch(req, {});

    expect(res.status).toBe(500);
    const body = await res.json() as { error: string };
    expect(body.error).toContain('GARMIN_EMAIL');
  });

  // ─── OAuth 2.0 Tests ───

  it('returns OAuth protected resource metadata', async () => {
    const req = new Request('http://localhost/.well-known/oauth-protected-resource');
    const res = await worker.fetch(req, {});

    expect(res.status).toBe(200);
    const body = await res.json() as { resource: string; authorization_servers: string[] };
    expect(body.resource).toBe('http://localhost');
    expect(body.authorization_servers).toContain('http://localhost');
  });

  it('returns OAuth authorization server metadata', async () => {
    const req = new Request('http://localhost/.well-known/oauth-authorization-server');
    const res = await worker.fetch(req, {});

    expect(res.status).toBe(200);
    const body = await res.json() as { token_endpoint: string; grant_types_supported: string[] };
    expect(body.token_endpoint).toBe('http://localhost/oauth/token');
    expect(body.grant_types_supported).toContain('authorization_code');
    expect(body.grant_types_supported).toContain('client_credentials');
  });

  it('handles OAuth client_credentials token exchange', async () => {
    const req = new Request('http://localhost/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials&client_id=test@example.com&client_secret=mypassword',
    });

    const res = await worker.fetch(req, {});

    expect(res.status).toBe(200);
    const body = await res.json() as { access_token: string; token_type: string };
    expect(body.token_type).toBe('Bearer');
    expect(body.access_token).toBeTruthy();

    // Verify the access token encodes the credentials
    const decoded = atob(body.access_token);
    expect(decoded).toBe('test@example.com:mypassword');
  });

  it('accepts OAuth Bearer token for MCP requests', async () => {
    // Step 1: Get token via OAuth
    const tokenReq = new Request('http://localhost/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials&client_id=test@example.com&client_secret=mypassword',
    });
    const tokenRes = await worker.fetch(tokenReq, {});
    const { access_token } = await tokenRes.json() as { access_token: string };

    // Step 2: Use token for MCP initialize
    const initReq = new Request('http://localhost/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${access_token}`,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'Gemini', version: '1.0' },
        },
      }),
    });

    const res = await worker.fetch(initReq, {});

    expect(res.status).toBe(200);
    const body = await res.json() as { result?: { serverInfo?: { name: string } } };
    expect(body.result?.serverInfo?.name).toBe('garmin-connect-mcp');
  });

  it('handles OAuth authorization_code flow', async () => {
    // Step 1: Authorize → get redirect with code
    const authReq = new Request(
      'http://localhost/oauth/authorize?client_id=test@example.com&redirect_uri=https://example.com/callback&response_type=code&state=xyz',
    );
    const authRes = await worker.fetch(authReq, {});

    expect(authRes.status).toBe(302);
    const location = authRes.headers.get('Location')!;
    const redirectUrl = new URL(location);
    expect(redirectUrl.searchParams.get('state')).toBe('xyz');
    const code = redirectUrl.searchParams.get('code')!;
    expect(code).toBeTruthy();

    // Step 2: Exchange code for token
    const tokenReq = new Request('http://localhost/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=authorization_code&code=${encodeURIComponent(code)}&client_id=test@example.com&client_secret=mypassword`,
    });
    const tokenRes = await worker.fetch(tokenReq, {});

    expect(tokenRes.status).toBe(200);
    const { access_token } = await tokenRes.json() as { access_token: string };
    expect(atob(access_token)).toBe('test@example.com:mypassword');
  });

  it('handles dynamic client registration', async () => {
    const req = new Request('http://localhost/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Gemini Spark',
        redirect_uris: ['https://example.com/callback'],
      }),
    });

    const res = await worker.fetch(req, {});

    expect(res.status).toBe(201);
    const body = await res.json() as { client_id: string; client_name: string };
    expect(body.client_id).toBeTruthy();
    expect(body.client_name).toBe('Gemini Spark');
  });
});
