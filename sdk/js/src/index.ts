/**
 * Secure-Login SDK â€” JavaScript / TypeScript
 * Client universel pour l'API secure-auth-api (navigateur & Node 18+).
 */

export interface Tokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface LoginResult extends Tokens {
  user?: unknown;
  mfa_required?: boolean;
  mfa_token?: string;
}

export interface RequestOptions {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
}

export class SecureAuthError extends Error {
  constructor(public status: number, public body: any) {
    super((body && body.error) || `HTTP ${status}`);
    this.name = 'SecureAuthError';
  }
}

export class SecureAuthClient {
  private _accessToken: string | null = null;
  private _refreshToken: string | null = null;
  private fetchImpl: typeof fetch;

  constructor(
    private baseUrl: string,
    options: { fetch?: typeof fetch } = {}
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.fetchImpl = options.fetch ?? fetch.bind(globalThis);
  }

  /* ---- tokens ---- */
  setTokens(access: string, refresh?: string) {
    this._accessToken = access;
    if (refresh) this._refreshToken = refresh;
  }
  getAccessToken() { return this._accessToken; }
  getRefreshToken() { return this._refreshToken; }
  clearTokens() { this._accessToken = null; this._refreshToken = null; }

  private async request<T>(path: string, opts: RequestOptions = {}, authed = true): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    };
    if (authed && this._accessToken) headers['Authorization'] = `Bearer ${this._accessToken}`;

    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method: opts.method || 'GET',
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new SecureAuthError(res.status, data);
    return data as T;
  }

  /* ---- auth core (spÃ©cification SDK obligatoire) ---- */

  /** CrÃ©er un compte. */
  async register(email: string, password: string): Promise<{ user_id: string; message: string }> {
    return this.request('/auth/register', { method: 'POST', body: { email, password } }, false);
  }

  /** Connexion. Si MFA actif : renvoie mfa_required + mfa_token â†’ utiliser loginMfa(). */
  async login(email: string, password: string, captchaToken?: string): Promise<LoginResult> {
    const r = await this.request<LoginResult>('/auth/login', {
      method: 'POST',
      body: { email, password, captcha_token: captchaToken },
    }, false);
    if (r.access_token) this.setTokens(r.access_token, r.refresh_token);
    return r;
  }

  /** Finalise une connexion MFA (TOTP ou code de rÃ©cupÃ©ration). */
  async loginMfa(mfaToken: string, code: string): Promise<LoginResult> {
    const r = await this.request<LoginResult>('/auth/mfa/verify', {
      method: 'POST',
      body: { mfa_token: mfaToken, code },
    }, false);
    if (r.access_token) this.setTokens(r.access_token, r.refresh_token);
    return r;
  }

  /** Rotation du refresh token â†’ nouveaux tokens stockÃ©s. */
  async refreshToken(): Promise<Tokens> {
    if (!this._refreshToken) throw new SecureAuthError(401, { error: 'No refresh token' });
    const r = await this.request<Tokens>('/auth/token/refresh', {
      method: 'POST',
      body: { refresh_token: this._refreshToken },
    }, false);
    this.setTokens(r.access_token, r.refresh_token);
    return r;
  }

  /** Utilisateur courant (+ scopes, mfa_enabled). */
  async getCurrentUser(): Promise<any> {
    return this.request('/auth/me');
  }

  /** DÃ©connexion de la session courante. */
  async logout(): Promise<void> {
    try { await this.request('/auth/logout', { method: 'POST', body: {} }); }
    finally { this.clearTokens(); }
  }

  /** VÃ©rifie une permission/scope cÃ´tÃ© serveur (via /auth/me). */
  async checkPermission(scope: string): Promise<boolean> {
    try {
      const me = await this.getCurrentUser();
      return Array.isArray(me.scopes) && me.scopes.includes(scope);
    } catch {
      return false;
    }
  }

  /* ---- bonus ---- */

  async logoutAll() { return this.request('/auth/logout-all', { method: 'POST', body: {} }); }
  async verifyEmail(token: string) {
    return this.request('/auth/verify-email', { method: 'POST', body: { token } }, false);
  }
  async forgotPassword(email: string) {
    return this.request('/auth/forgot-password', { method: 'POST', body: { email } }, false);
  }
  async resetPassword(token: string, newPassword: string) {
    return this.request('/auth/reset-password', { method: 'POST', body: { token, new_password: newPassword } }, false);
  }
  async changePassword(currentPassword: string, newPassword: string) {
    return this.request('/auth/change-password', { method: 'POST', body: {
      current_password: currentPassword, new_password: newPassword } });
  }
  async changeEmail(password: string, newEmail: string) {
    return this.request('/auth/change-email', { method: 'POST', body: {
      password, new_email: newEmail } });
  }
  async deleteAccount(password: string) {
    const r = await this.request('/auth/account', { method: 'DELETE', body: { password } });
    this.clearTokens();
    return r;
  }
  async listSessions() { return this.request('/auth/sessions'); }

  /* MFA */
  async enableMfa() { return this.request('/auth/mfa/enable', { method: 'POST' }); }
  async confirmMfa(code: string) {
    return this.request('/auth/mfa/verify', { method: 'POST', body: { code } });
  }

  /* Passkeys (le navigateur doit fournir les credentials WebAuthn) */
  async passkeyRegisterOptions() {
    return this.request<any>('/auth/passkey/register/options', { method: 'POST' });
  }
  async passkeyRegister(name: string, response: unknown) {
    return this.request('/auth/passkey/register', { method: 'POST', body: { name, response } });
  }
  async passkeyLoginOptions(email: string) {
    return this.request<any>('/auth/passkey/login/options', { method: 'POST', body: { email } }, false);
  }
  async passkeyLogin(challengeId: string, response: unknown) {
    const r = await this.request<LoginResult>('/auth/passkey/login', {
      method: 'POST',
      body: { challenge_id: challengeId, response },
    }, false);
    if (r.access_token) this.setTokens(r.access_token, r.refresh_token);
    return r;
  }

  /* Admin */
  async adminListUsers(q = '', limit = 50, offset = 0) {
    return this.request(`/admin/users?q=${encodeURIComponent(q)}&limit=${limit}&offset=${offset}`);
  }
  async adminBlockIp(ip: string, mode: 'blacklist' | 'whitelist', reason?: string, expiresInMinutes?: number) {
    return this.request('/admin/block-ip', { method: 'POST', body: {
      ip, mode, reason, expires_in_minutes: expiresInMinutes } });
  }
  async adminSuspiciousIps() { return this.request('/admin/suspicious-ips'); }
  async adminDoubleAccounts() { return this.request('/admin/double-accounts'); }
}
