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

  it('handles Gemini POST initialize request with Accept: application/json', async () => {
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

    const env = { GARMIN_EMAIL: 'test@example.com', GARMIN_PASSWORD: 'pass' };
    const res = await worker.fetch(req, env);

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

    // Env does not have credentials, worker extracts them from Basic Auth!
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
});
