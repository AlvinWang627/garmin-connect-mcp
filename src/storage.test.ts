import { describe, it, expect } from 'vitest';
import { MemoryTokenStorage, KVTokenStorage, type AuthTokens } from './client/storage';

describe('Storage Classes', () => {
  it('MemoryTokenStorage saves and loads tokens', async () => {
    const storage = new MemoryTokenStorage();
    expect(await storage.load()).toBeNull();

    const sampleTokens: AuthTokens = {
      oauth1Token: { oauth_token: 'tok1', oauth_token_secret: 'sec1' },
      oauth2Token: {
        access_token: 'acc2',
        refresh_token: 'ref2',
        token_type: 'Bearer',
        expires_in: 3600,
        expires_at: 10000,
        refresh_token_expires_in: 7200,
        refresh_token_expires_at: 20000,
      },
      profile: { displayName: 'testuser', profileId: 12345 },
    };

    await storage.save(sampleTokens);
    const loaded = await storage.load();

    expect(loaded).toEqual(sampleTokens);
  });

  it('KVTokenStorage saves and loads tokens via KV mock', async () => {
    const store = new Map<string, string>();
    const mockKv = {
      async get(key: string) {
        return store.get(key) ?? null;
      },
      async put(key: string, value: string) {
        store.set(key, value);
      },
    };

    const storage = new KVTokenStorage(mockKv);
    expect(await storage.load()).toBeNull();

    const sampleTokens: AuthTokens = {
      profile: { displayName: 'kvuser', profileId: 999 },
    };

    await storage.save(sampleTokens);
    const loaded = await storage.load();

    expect(loaded).toEqual(sampleTokens);
  });
});
