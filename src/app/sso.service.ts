import { Injectable } from '@angular/core';

export interface OidcConfig {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userInfoEndpoint: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  audience: string;
}

export interface OidcTokenResponse {
  access_token?: string;
  id_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
  error?: string;
  error_description?: string;
  [key: string]: unknown;
}

export interface OidcSession {
  state: string;
  nonce: string;
  codeVerifier: string;
  createdAt: number;
}

export interface SamlConfig {
  entityId: string;
  acsUrl: string;
  ssoUrl: string;
  relayState: string;
  nameIdPolicy: string;
}

export interface SamlResponseSummary {
  relayState: string | null;
  decodedXml: string | null;
  destination: string | null;
  issuer: string | null;
  nameId: string | null;
  statusCode: string | null;
}

const OIDC_SESSION_KEY = 'sso-client:oidc-session';

@Injectable({ providedIn: 'root' })
export class SsoService {
  async discoverOidc(issuer: string): Promise<Partial<OidcConfig>> {
    const normalizedIssuer = issuer.replace(/\/$/, '');
    const response = await fetch(`${normalizedIssuer}/.well-known/openid-configuration`);

    if (!response.ok) {
      throw new Error(`Discovery failed with HTTP ${response.status}`);
    }

    const metadata = await response.json() as {
      authorization_endpoint?: string;
      token_endpoint?: string;
      userinfo_endpoint?: string;
      issuer?: string;
    };

    return {
      issuer: metadata.issuer ?? normalizedIssuer,
      authorizationEndpoint: metadata.authorization_endpoint ?? '',
      tokenEndpoint: metadata.token_endpoint ?? '',
      userInfoEndpoint: metadata.userinfo_endpoint ?? '',
    };
  }

  async createOidcAuthorizationUrl(config: OidcConfig): Promise<string> {
    const state = this.randomUrlSafeString();
    const nonce = this.randomUrlSafeString();
    const codeVerifier = this.randomUrlSafeString(64);
    const codeChallenge = await this.sha256Base64Url(codeVerifier);

    const session: OidcSession = {
      state,
      nonce,
      codeVerifier,
      createdAt: Date.now(),
    };

    localStorage.setItem(OIDC_SESSION_KEY, JSON.stringify(session));

    const url = new URL(config.authorizationEndpoint);
    url.searchParams.set('client_id', config.clientId);
    url.searchParams.set('redirect_uri', config.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', config.scope);
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');

    if (config.audience.trim()) {
      url.searchParams.set('audience', config.audience.trim());
    }

    return url.toString();
  }

  getOidcCallbackParams(search: string): { code: string | null; state: string | null; error: string | null } {
    const params = new URLSearchParams(search);

    return {
      code: params.get('code'),
      state: params.get('state'),
      error: params.get('error'),
    };
  }

  async exchangeOidcCode(config: OidcConfig, code: string, state: string): Promise<OidcTokenResponse> {
    const session = this.readOidcSession();

    if (!session) {
      throw new Error('No OIDC login session was found in localStorage.');
    }

    if (session.state !== state) {
      throw new Error('OIDC state mismatch. The callback was not created by this client.');
    }

    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('client_id', config.clientId);
    body.set('code', code);
    body.set('redirect_uri', config.redirectUri);
    body.set('code_verifier', session.codeVerifier);

    const response = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    });

    const payload = await response.json() as OidcTokenResponse;

    if (!response.ok) {
      throw new Error(payload.error_description ?? payload.error ?? `Token exchange failed with HTTP ${response.status}`);
    }

    return payload;
  }

  async fetchUserInfo(config: OidcConfig, accessToken: string): Promise<unknown> {
    const response = await fetch(config.userInfoEndpoint, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    const payload = await response.json() as unknown;

    if (!response.ok) {
      throw new Error(`UserInfo failed with HTTP ${response.status}`);
    }

    return payload;
  }

  clearOidcSession(): void {
    localStorage.removeItem(OIDC_SESSION_KEY);
  }

  decodeJwt(token: string): unknown {
    const [, payload] = token.split('.');

    if (!payload) {
      return null;
    }

    return JSON.parse(this.base64UrlDecode(payload)) as unknown;
  }

  createSamlAuthnRequest(config: SamlConfig): string {
    const id = `_${crypto.randomUUID()}`;
    const issueInstant = new Date().toISOString();
    const nameIdPolicy = config.nameIdPolicy.trim()
      ? `<samlp:NameIDPolicy Format="${this.escapeXml(config.nameIdPolicy)}" AllowCreate="true" />`
      : '';

    return [
      `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`,
      `  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`,
      `  ID="${id}"`,
      `  Version="2.0"`,
      `  IssueInstant="${issueInstant}"`,
      `  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`,
      `  AssertionConsumerServiceURL="${this.escapeXml(config.acsUrl)}"`,
      `  Destination="${this.escapeXml(config.ssoUrl)}">`,
      `  <saml:Issuer>${this.escapeXml(config.entityId)}</saml:Issuer>`,
      `  ${nameIdPolicy}`,
      `</samlp:AuthnRequest>`,
    ].filter(Boolean).join('\n');
  }

  launchSamlPostBinding(config: SamlConfig): void {
    const requestXml = this.createSamlAuthnRequest(config);
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = config.ssoUrl;
    form.style.display = 'none';

    form.append(
      this.hiddenInput('SAMLRequest', this.base64Encode(requestXml)),
      this.hiddenInput('RelayState', config.relayState),
    );

    document.body.appendChild(form);
    form.submit();
  }

  createSamlRedirectUrl(config: SamlConfig): string {
    const url = new URL(config.ssoUrl);
    url.searchParams.set('SAMLRequest', this.base64Encode(this.createSamlAuthnRequest(config)));

    if (config.relayState.trim()) {
      url.searchParams.set('RelayState', config.relayState);
    }

    return url.toString();
  }

  readSamlResponseFromUrl(search: string): SamlResponseSummary {
    const params = new URLSearchParams(search);
    const encodedResponse = params.get('SAMLResponse');
    const decodedXml = encodedResponse ? this.base64Decode(encodedResponse) : null;

    return {
      relayState: params.get('RelayState'),
      decodedXml,
      destination: decodedXml ? this.extractXmlAttribute(decodedXml, 'Response', 'Destination') : null,
      issuer: decodedXml ? this.extractXmlText(decodedXml, 'Issuer') : null,
      nameId: decodedXml ? this.extractXmlText(decodedXml, 'NameID') : null,
      statusCode: decodedXml ? this.extractXmlAttribute(decodedXml, 'StatusCode', 'Value') : null,
    };
  }

  private readOidcSession(): OidcSession | null {
    const raw = localStorage.getItem(OIDC_SESSION_KEY);

    if (!raw) {
      return null;
    }

    return JSON.parse(raw) as OidcSession;
  }

  private hiddenInput(name: string, value: string): HTMLInputElement {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    input.value = value;

    return input;
  }

  private randomUrlSafeString(length = 32): string {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);

    return this.base64UrlEncode(String.fromCharCode(...bytes));
  }

  private async sha256Base64Url(value: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));

    return this.base64UrlEncode(String.fromCharCode(...new Uint8Array(digest)));
  }

  private base64Encode(value: string): string {
    const bytes = new TextEncoder().encode(value);
    let binary = '';
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });

    return btoa(binary);
  }

  private base64Decode(value: string): string {
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));

    return new TextDecoder().decode(bytes);
  }

  private base64UrlEncode(value: string): string {
    return btoa(value)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  private base64UrlDecode(value: string): string {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '=');

    return this.base64Decode(padded);
  }

  private extractXmlText(xml: string, tagName: string): string | null {
    const documentXml = new DOMParser().parseFromString(xml, 'text/xml');
    const node = Array.from(documentXml.getElementsByTagName('*'))
      .find((element) => element.localName === tagName);

    return node?.textContent ?? null;
  }

  private extractXmlAttribute(xml: string, tagName: string, attributeName: string): string | null {
    const documentXml = new DOMParser().parseFromString(xml, 'text/xml');
    const node = Array.from(documentXml.getElementsByTagName('*'))
      .find((element) => element.localName === tagName);

    return node?.getAttribute(attributeName) ?? null;
  }

  private escapeXml(value: string): string {
    return value
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/'/g, '&apos;');
  }
}
