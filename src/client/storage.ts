import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export type OAuth1Token = {
  oauth_token: string;
  oauth_token_secret: string;
};

export type OAuth2Token = {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  expires_at: number;
  refresh_token_expires_in: number;
  refresh_token_expires_at: number;
};

export type UserProfile = {
  displayName: string;
  profileId: number;
};

export type AuthTokens = {
  oauth1Token?: OAuth1Token | null;
  oauth2Token?: OAuth2Token | null;
  profile?: UserProfile | null;
};

export interface TokenStorage {
  load(): Promise<AuthTokens | null> | AuthTokens | null;
  save(data: AuthTokens): Promise<void> | void;
}

export class FileTokenStorage implements TokenStorage {
  private tokenDir: string;
  private oauth1Path: string;
  private oauth2Path: string;
  private profilePath: string;

  constructor(customDir?: string) {
    let baseDir = '/tmp';
    try {
      if (typeof os.homedir === 'function') {
        baseDir = os.homedir();
      }
    } catch {
      baseDir = '/tmp';
    }
    this.tokenDir = customDir ?? path.join(baseDir, '.garmin-mcp');
    this.oauth1Path = path.join(this.tokenDir, 'oauth1_token.json');
    this.oauth2Path = path.join(this.tokenDir, 'oauth2_token.json');
    this.profilePath = path.join(this.tokenDir, 'profile.json');
  }

  load(): AuthTokens | null {
    try {
      if (typeof fs.existsSync !== 'function' || typeof fs.readFileSync !== 'function') {
        return null;
      }
      let oauth1Token: OAuth1Token | null = null;
      let oauth2Token: OAuth2Token | null = null;
      let profile: UserProfile | null = null;

      if (fs.existsSync(this.oauth1Path)) {
        oauth1Token = JSON.parse(fs.readFileSync(this.oauth1Path, 'utf-8'));
      }
      if (fs.existsSync(this.oauth2Path)) {
        oauth2Token = JSON.parse(fs.readFileSync(this.oauth2Path, 'utf-8'));
      }
      if (fs.existsSync(this.profilePath)) {
        profile = JSON.parse(fs.readFileSync(this.profilePath, 'utf-8'));
      }

      return { oauth1Token, oauth2Token, profile };
    } catch {
      return null;
    }
  }

  save(data: AuthTokens): void {
    try {
      if (typeof fs.existsSync !== 'function' || typeof fs.writeFileSync !== 'function') {
        return;
      }
      if (!fs.existsSync(this.tokenDir) && typeof fs.mkdirSync === 'function') {
        fs.mkdirSync(this.tokenDir, { recursive: true, mode: 0o700 });
      }

      if (data.oauth1Token) {
        fs.writeFileSync(this.oauth1Path, JSON.stringify(data.oauth1Token, null, 2), { mode: 0o600 });
      }
      if (data.oauth2Token) {
        fs.writeFileSync(this.oauth2Path, JSON.stringify(data.oauth2Token, null, 2), { mode: 0o600 });
      }
      if (data.profile) {
        fs.writeFileSync(this.profilePath, JSON.stringify(data.profile, null, 2), { mode: 0o600 });
      }
    } catch (e) {
      console.error('Failed to save tokens to file:', e);
    }
  }
}

export class MemoryTokenStorage implements TokenStorage {
  private tokens: AuthTokens | null = null;

  load(): AuthTokens | null {
    return this.tokens;
  }

  save(data: AuthTokens): void {
    this.tokens = { ...data };
  }
}

export interface KVNamespaceBinding {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete?(key: string): Promise<void>;
}

export class KVTokenStorage implements TokenStorage {
  constructor(private kv: KVNamespaceBinding, private keyPrefix = 'garmin_tokens:') {}

  async load(): Promise<AuthTokens | null> {
    try {
      const data = await this.kv.get(`${this.keyPrefix}data`);
      if (data) {
        return JSON.parse(data) as AuthTokens;
      }
    } catch (e) {
      console.error('Failed to load tokens from KV:', e);
    }
    return null;
  }

  async save(data: AuthTokens): Promise<void> {
    try {
      await this.kv.put(`${this.keyPrefix}data`, JSON.stringify(data));
    } catch (e) {
      console.error('Failed to save tokens to KV:', e);
    }
  }
}
