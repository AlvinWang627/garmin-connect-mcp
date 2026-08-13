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
});
