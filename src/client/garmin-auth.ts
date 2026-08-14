import axios from 'axios';
import { wrapper } from 'axios-cookiejar-support';
import { CookieJar, type SerializedCookieJar } from 'tough-cookie';
import OAuth from 'oauth-1.0a';
import crypto from 'node:crypto';
import {
  FileTokenStorage,
  type TokenStorage,
  type OAuth1Token,
  type OAuth2Token,
  type UserProfile,
} from './storage';

const OAUTH_CONSUMER_URL = 'https://thegarth.s3.amazonaws.com/oauth_consumer.json';
const SSO_EMBED = 'https://sso.garmin.com/sso/embed';
const SSO_SIGNIN = 'https://sso.garmin.com/sso/signin';
const SSO_ORIGIN = 'https://sso.garmin.com';
const GARMIN_CONNECT_API = 'https://connectapi.garmin.com';
const OAUTH_PREAUTHORIZED = `${GARMIN_CONNECT_API}/oauth-service/oauth/preauthorized`;
const OAUTH_EXCHANGE = `${GARMIN_CONNECT_API}/oauth-service/oauth/exchange/user/2.0`;
const PROFILE_URL = `${GARMIN_CONNECT_API}/userprofile-service/socialProfile`;

const SSO_CLIENT_ID = 'GarminConnect';
const SSO_LOCALE = 'en';
const SSO_WIDGET_ID = 'gauth-widget';

const USER_AGENT_MOBILE = 'com.garmin.android.apps.connectmobile';
const USER_AGENT_BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

const CSRF_REGEX = /name=["']_csrf["'][^>]*value=["'](.+?)["']/i;
const TICKET_REGEX = /(?:[?&]|\b)ticket=([^"'&<\s]+)/i;
const TITLE_REGEX = /<title[^>]*>([\s\S]*?)<\/title>/i;
const SSO_VERIFY_MFA = 'https://sso.garmin.com/sso/verifyMFA/loginEnterMfaCode';

const MAX_REQUEST_RETRIES = 3;
const TOKEN_EXPIRY_BUFFER_SECONDS = 60;

type OAuthConsumer = {
  consumer_key: string;
  consumer_secret: string;
};

type SigninParams = {
  id: string;
  embedWidget: boolean;
  locale: string;
  gauthHost: string;
};

type LoginState =
  | { kind: 'ticket'; ticket: string }
  | { kind: 'mfa'; challenge: GarminMfaChallenge };

function isMfaResponse(html: string, title: string): boolean {
  const lowerHtml = html.toLowerCase();
  const lowerTitle = title.toLowerCase();

  return lowerTitle.includes('mfa')
    || lowerHtml.includes('loginentermfacode')
    || lowerHtml.includes('verifymfa')
    || lowerHtml.includes('submit-mfa-verification-code-form')
    || lowerHtml.includes('name="mfa-code"')
    || lowerHtml.includes("name='mfa-code'")
    || lowerHtml.includes('id="mfa-code"')
    || lowerHtml.includes("id='mfa-code'")
    || lowerHtml.includes('enter security code')
    || lowerHtml.includes('security code')
    || lowerHtml.includes('code sent to')
    || lowerHtml.includes('verification code')
    || /mfarequired\s*[=:"']+\s*true/i.test(html)
    || /performmfacheck\s*[=:"']+\s*true/i.test(html);
}

function getResponseUrl(response: unknown): string {
  const request = (response as {
    request?: {
      responseURL?: unknown;
      res?: { responseUrl?: unknown };
    };
  }).request;

  if (typeof request?.responseURL === 'string') return request.responseURL;
  if (typeof request?.res?.responseUrl === 'string') return request.res.responseUrl;
  return '';
}

/**
 * Serializable state returned when Garmin pauses login for MFA.
 * It contains the SSO cookies and CSRF token needed by the next request,
 * but never the Garmin password.
 */
export type GarminMfaChallenge = {
  version: 1;
  email: string;
  createdAt: number;
  expiresAt: number;
  mfaCsrfToken: string;
  signinParams: SigninParams;
  cookieJar: SerializedCookieJar;
};

export type RequestOptions = {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
};

export class GarminAuth {
  private email: string;
  private password: string;
  private consumer: OAuthConsumer | null = null;
  private oauth1Token: OAuth1Token | null = null;
  private oauth2Token: OAuth2Token | null = null;
  private profile: UserProfile | null = null;
  private isAuthenticated = false;
  private promptMfa?: () => Promise<string>;
  private tokenStorage: TokenStorage;
  private tokensLoaded = false;

  get displayName(): string {
    return this.profile?.displayName ?? '';
  }

  get userProfilePk(): number {
    return this.profile?.profileId ?? 0;
  }

  constructor(
    email: string,
    password: string,
    promptMfa?: () => Promise<string>,
    tokenStorage?: TokenStorage,
  ) {
    this.email = email;
    this.password = password;
    this.promptMfa = promptMfa;
    this.tokenStorage = tokenStorage ?? new FileTokenStorage();
  }

  /**
   * Starts a login for a remote caller. If Garmin requires MFA, the caller
   * receives a serializable challenge and can complete it later with
   * verifyMfa(). If MFA is not required, authentication is completed here.
   */
  async startMfaLogin(): Promise<GarminMfaChallenge | null> {
    this.validateCredentials();
    await this.fetchOAuthConsumer();

    const state = await this.beginLogin();
    if (state.kind === 'mfa') return state.challenge;

    await this.finishTicketLogin(state.ticket);
    this.isAuthenticated = true;
    return null;
  }

  /** Completes a previously started remote MFA login and saves the tokens. */
  async verifyMfa(challenge: GarminMfaChallenge, code: string): Promise<void> {
    if (!this.email || challenge.email !== this.email) {
      throw new Error('MFA challenge does not belong to this account');
    }
    if (!code || !/^\d{4,12}$/.test(code.trim())) {
      throw new Error('MFA code must contain 4 to 12 digits');
    }
    if (challenge.version !== 1 || Date.now() >= challenge.expiresAt) {
      throw new Error('MFA challenge has expired');
    }

    await this.fetchOAuthConsumer();
    const ssoClient = wrapper(axios.create({
      jar: CookieJar.fromJSON(challenge.cookieJar),
      withCredentials: true,
    }));

    const mfaResponse = await ssoClient.post(SSO_VERIFY_MFA, new URLSearchParams({
      'mfa-code': code.trim(),
      embed: 'true',
      _csrf: challenge.mfaCsrfToken,
      fromPage: 'setupEnterMfaCode',
    }).toString(), {
      params: {
        ...challenge.signinParams,
        clientId: SSO_CLIENT_ID,
        service: SSO_EMBED,
        source: SSO_EMBED,
        redirectAfterAccountLoginUrl: SSO_EMBED,
        redirectAfterAccountCreationUrl: SSO_EMBED,
      },
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': USER_AGENT_BROWSER,
        Origin: SSO_ORIGIN,
        Referer: SSO_SIGNIN,
        Dnt: '1',
      },
    });

    const ticketMatch = TICKET_REGEX.exec(String(mfaResponse.data));
    if (!ticketMatch) throw new Error('MFA verification failed; check the latest code from Garmin');

    await this.finishTicketLogin(ticketMatch[1]!);
    this.isAuthenticated = true;
  }

  async request<T>(endpoint: string, options?: RequestOptions): Promise<T> {
    await this.ensureAuthenticated();

    const url = endpoint.startsWith('http') ? endpoint : `${GARMIN_CONNECT_API}${endpoint}`;
    const method = (options?.method ?? 'GET').toUpperCase();
    const reqHeaders: Record<string, string> = {
      Authorization: `Bearer ${this.oauth2Token!.access_token}`,
      'User-Agent': USER_AGENT_MOBILE,
      ...options?.headers,
    };

    if (options?.body && !reqHeaders['Content-Type']) {
      reqHeaders['Content-Type'] = 'application/json';
    }

    for (let attempt = 0; attempt <= MAX_REQUEST_RETRIES; attempt++) {
      try {
        const response = await axios<T>({
          url,
          method,
          headers: reqHeaders,
          data: options?.body,
        });
        return response.data;
      } catch (error: unknown) {
        if (!axios.isAxiosError(error)) throw error;

        const status = error.response?.status;

        if (status === 401 && attempt === 0) {
          await this.refreshOrRelogin();
          reqHeaders.Authorization = `Bearer ${this.oauth2Token!.access_token}`;
          continue;
        }

        if ((status === 429 || (status && status >= 500)) && attempt < MAX_REQUEST_RETRIES) {
          const delay = Math.pow(2, attempt) * 1000;
          await new Promise((resolve) => setTimeout(resolve, delay));
          continue;
        }

        throw error;
      }
    }

    throw new Error('Max retries exceeded');
  }

  private async ensureAuthenticated(): Promise<void> {
    await this.loadTokens();

    if (this.isAuthenticated && this.oauth2Token && !this.isOAuth2Expired() && this.profile) return;

    if (this.oauth1Token && this.oauth2Token && !this.isOAuth2Expired() && this.profile) {
      this.isAuthenticated = true;
      return;
    }

    if (this.oauth1Token && this.oauth2Token && !this.isOAuth2Expired() && !this.profile) {
      await this.fetchProfile();
      await this.saveTokens();
      this.isAuthenticated = true;
      return;
    }

    if (this.oauth1Token) {
      await this.exchangeOAuth1ForOAuth2();
      await this.fetchProfile();
      await this.saveTokens();
      this.isAuthenticated = true;
      return;
    }

    await this.login();
    this.isAuthenticated = true;
  }

  private async refreshOrRelogin(): Promise<void> {
    this.isAuthenticated = false;

    if (this.oauth1Token) {
      try {
        await this.exchangeOAuth1ForOAuth2();
        if (!this.profile) await this.fetchProfile();
        await this.saveTokens();
        this.isAuthenticated = true;
        return;
      } catch (error) {
        console.error('OAuth2 refresh failed, will re-login:', error);
      }
    }

    await this.login();
    this.isAuthenticated = true;
  }

  private async login(): Promise<void> {
    this.validateCredentials();

    console.error('Authenticating with Garmin Connect...');

    await this.fetchOAuthConsumer();

    const state = await this.beginLogin();
    if (state.kind === 'mfa') {
      if (!this.promptMfa) {
        throw new Error(
          'MFA is required but no MFA handler is available. Run the interactive setup or use the remote MFA setup endpoint.',
        );
      }
      await this.completeMfaLogin(state.challenge, await this.promptMfa());
    } else {
      await this.finishTicketLogin(state.ticket);
    }

    console.error('Authentication successful');
  }

  private validateCredentials(): void {
    if (!this.email || !this.password) {
      throw new Error(
        'Garmin Connect credentials are not configured. ' +
        'Set GARMIN_EMAIL and GARMIN_PASSWORD as Cloudflare Worker secrets, ' +
        'or provide them via Basic Auth (Client ID = email, Client Secret = password).',
      );
    }
  }

  private async fetchProfile(): Promise<void> {
    const response = await axios.get<Record<string, unknown>>(PROFILE_URL, {
      headers: {
        Authorization: `Bearer ${this.oauth2Token!.access_token}`,
        'User-Agent': USER_AGENT_MOBILE,
      },
    });

    const displayName = response.data.displayName as string;
    const profileId = response.data.profileId as number ?? response.data.userProfileNumber as number;

    if (!displayName) throw new Error('Failed to get display name from profile');

    this.profile = { displayName, profileId };
  }

  private async fetchOAuthConsumer(): Promise<void> {
    if (this.consumer) return;

    const response = await axios.get<OAuthConsumer>(OAUTH_CONSUMER_URL);
    this.consumer = response.data;
  }

  private async beginLogin(): Promise<LoginState> {
    const jar = new CookieJar();
    const ssoClient = wrapper(axios.create({ jar, withCredentials: true }));

    await ssoClient.get(SSO_EMBED, {
      params: { clientId: SSO_CLIENT_ID, locale: SSO_LOCALE, service: SSO_EMBED },
      headers: { 'User-Agent': USER_AGENT_BROWSER },
    });

    const signinParams: SigninParams = {
      id: SSO_WIDGET_ID,
      embedWidget: true,
      locale: SSO_LOCALE,
      gauthHost: SSO_EMBED,
    };

    const signinResponse = await ssoClient.get(SSO_SIGNIN, {
      params: signinParams,
      headers: { 'User-Agent': USER_AGENT_BROWSER },
    });

    const csrfMatch = CSRF_REGEX.exec(signinResponse.data);
    if (!csrfMatch) throw new Error('Failed to extract CSRF token from SSO');
    const csrfToken = csrfMatch[1];

    const loginResponse = await ssoClient.post(SSO_SIGNIN, new URLSearchParams({
      username: this.email,
      password: this.password,
      embed: 'true',
      _csrf: csrfToken!,
    }).toString(), {
      params: {
        ...signinParams,
        clientId: SSO_CLIENT_ID,
        service: SSO_EMBED,
        source: SSO_EMBED,
        redirectAfterAccountLoginUrl: SSO_EMBED,
        redirectAfterAccountCreationUrl: SSO_EMBED,
      },
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': USER_AGENT_BROWSER,
        Origin: SSO_ORIGIN,
        Referer: SSO_SIGNIN,
        Dnt: '1',
      },
    });

    const responseHtml: string = loginResponse.data;

    const titleMatch = TITLE_REGEX.exec(responseHtml);
    const title = titleMatch?.[1] ?? '';
    const responseUrl = getResponseUrl(loginResponse);
    const responseUrlIsMfa = /loginentermfacode|verifymfa/i.test(responseUrl);

    if (isMfaResponse(responseHtml, title) || responseUrlIsMfa) {
      const mfaCsrfMatch = CSRF_REGEX.exec(responseHtml);
      if (!mfaCsrfMatch) throw new Error('Failed to extract CSRF token for MFA');

      const cookieJar = jar.toJSON();
      if (!cookieJar) throw new Error('Failed to serialize Garmin MFA session');

      return {
        kind: 'mfa',
        challenge: {
          version: 1,
          email: this.email,
          createdAt: Date.now(),
          expiresAt: Date.now() + 10 * 60 * 1000,
          mfaCsrfToken: mfaCsrfMatch[1]!,
          signinParams,
          cookieJar,
        },
      };
    }

    const ticketMatch = TICKET_REGEX.exec(responseHtml);
    if (!ticketMatch) {
      const normalizedTitle = title.replace(/\s+/g, ' ').trim();
      throw new Error(
        normalizedTitle
          ? `Login failed: Garmin returned the page "${normalizedTitle}" without a service ticket; check credentials or wait if Garmin SSO is rate-limiting the account`
          : 'Login failed: Garmin did not return a service ticket; check credentials or wait if Garmin SSO is rate-limiting the account',
      );
    }

    return { kind: 'ticket', ticket: ticketMatch[1]! };
  }

  private async completeMfaLogin(challenge: GarminMfaChallenge, code: string): Promise<void> {
    await this.verifyMfa(challenge, code);
  }

  private async finishTicketLogin(ticket: string): Promise<void> {
    await this.exchangeTicketForOAuth1(ticket);
    await this.exchangeOAuth1ForOAuth2();
    await this.fetchProfile();
    await this.saveTokens();
  }

  private async exchangeTicketForOAuth1(ticket: string): Promise<void> {
    await this.fetchOAuthConsumer();

    const oauth = new OAuth({
      consumer: { key: this.consumer!.consumer_key, secret: this.consumer!.consumer_secret },
      signature_method: 'HMAC-SHA1',
      hash_function: (baseString, key) =>
        crypto.createHmac('sha1', key).update(baseString).digest('base64'),
    });

    const url = `${OAUTH_PREAUTHORIZED}?${new URLSearchParams({
      ticket,
      'login-url': SSO_EMBED,
      'accepts-mfa-tokens': 'true',
    })}`;

    const requestData = { url, method: 'GET' };
    const authHeader = oauth.toHeader(oauth.authorize(requestData));

    const response = await axios.get(url, {
      headers: {
        ...authHeader,
        'User-Agent': USER_AGENT_MOBILE,
      },
    });

    const params = new URLSearchParams(response.data);
    const oauthToken = params.get('oauth_token');
    const oauthTokenSecret = params.get('oauth_token_secret');

    if (!oauthToken || !oauthTokenSecret) {
      throw new Error('Failed to obtain OAuth1 token');
    }

    this.oauth1Token = { oauth_token: oauthToken, oauth_token_secret: oauthTokenSecret };
  }

  private async exchangeOAuth1ForOAuth2(): Promise<void> {
    await this.fetchOAuthConsumer();

    if (!this.oauth1Token) throw new Error('OAuth1 token required for OAuth2 exchange');

    const oauth = new OAuth({
      consumer: { key: this.consumer!.consumer_key, secret: this.consumer!.consumer_secret },
      signature_method: 'HMAC-SHA1',
      hash_function: (baseString, key) =>
        crypto.createHmac('sha1', key).update(baseString).digest('base64'),
    });

    const token: OAuth.Token = {
      key: this.oauth1Token.oauth_token,
      secret: this.oauth1Token.oauth_token_secret,
    };

    const requestData = { url: OAUTH_EXCHANGE, method: 'POST' };
    const authData = oauth.authorize(requestData, token);

    const queryParams = new URLSearchParams();
    for (const [key, value] of Object.entries(authData)) {
      queryParams.set(key, String(value));
    }

    const response = await axios.post<OAuth2Token>(
      `${OAUTH_EXCHANGE}?${queryParams}`,
      null,
      {
        headers: {
          'User-Agent': USER_AGENT_MOBILE,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      },
    );

    const now = Math.floor(Date.now() / 1000);
    this.oauth2Token = {
      ...response.data,
      expires_at: now + response.data.expires_in,
      refresh_token_expires_at: now + response.data.refresh_token_expires_in,
    };
  }

  private isOAuth2Expired(): boolean {
    if (!this.oauth2Token) return true;
    return this.oauth2Token.expires_at < Math.floor(Date.now() / 1000) + TOKEN_EXPIRY_BUFFER_SECONDS;
  }

  private async loadTokens(): Promise<void> {
    if (this.tokensLoaded) return;
    try {
      const stored = await this.tokenStorage.load();
      if (stored) {
        if (stored.oauth1Token) this.oauth1Token = stored.oauth1Token;
        if (stored.oauth2Token) this.oauth2Token = stored.oauth2Token;
        if (stored.profile) this.profile = stored.profile;
      }
    } catch {
      this.oauth1Token = null;
      this.oauth2Token = null;
      this.profile = null;
    } finally {
      this.tokensLoaded = true;
    }
  }

  private async saveTokens(): Promise<void> {
    try {
      await this.tokenStorage.save({
        oauth1Token: this.oauth1Token,
        oauth2Token: this.oauth2Token,
        profile: this.profile,
      });
    } catch (e) {
      console.error('Failed to save tokens:', e);
    }
  }
}
