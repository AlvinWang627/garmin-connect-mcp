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

  it('returns 401 when AUTH_TOKEN is set but missing in request', async () => {
    const req = new Request('http://localhost/mcp', { method: 'POST' });
    const env = { AUTH_TOKEN: 'secret123' };
    const res = await worker.fetch(req, env);

    expect(res.status).toBe(401);
  });

  it('allows query parameter auth token', async () => {
    const req = new Request('http://localhost/health?token=secret123', { method: 'GET' });
    const env = { AUTH_TOKEN: 'secret123' };
    const res = await worker.fetch(req, env);

    expect(res.status).toBe(200);
  });

  it('returns 500 when GARMIN_EMAIL / GARMIN_PASSWORD are missing', async () => {
    const req = new Request('http://localhost/mcp', {
      method: 'POST',
      headers: { Authorization: 'Bearer secret123' },
    });
    const env = { AUTH_TOKEN: 'secret123' };
    const res = await worker.fetch(req, env);

    expect(res.status).toBe(500);
    const body = await res.json() as { error: string };
    expect(body.error).toContain('GARMIN_EMAIL');
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
