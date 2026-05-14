import { CommonModule, JsonPipe } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { OidcConfig, OidcTokenResponse, SamlConfig, SamlResponseSummary, SsoService } from './sso.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule, JsonPipe],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css',
})
export class AppComponent implements OnInit {
  readonly title = 'SSO Client';

  activeTab: 'oidc' | 'saml' = 'oidc';
  busy = false;
  status = 'Configure your provider, then start a login flow.';
  error = '';

  oidcConfig: OidcConfig = {
    issuer: 'https://YOUR_ISSUER_DOMAIN',
    authorizationEndpoint: 'https://YOUR_ISSUER_DOMAIN/oauth2/v1/authorize',
    tokenEndpoint: 'https://YOUR_ISSUER_DOMAIN/oauth2/v1/token',
    userInfoEndpoint: 'https://YOUR_ISSUER_DOMAIN/oauth2/v1/userinfo',
    clientId: 'sso-client-spa',
    redirectUri: `${window.location.origin}${window.location.pathname}`,
    scope: 'openid profile email',
    audience: '',
  };

  oidcTokens: OidcTokenResponse | null = null;
  oidcIdTokenClaims: unknown = null;
  oidcUserInfo: unknown = null;

  samlConfig: SamlConfig = {
    entityId: `${window.location.origin}/saml/metadata`,
    acsUrl: `${window.location.origin}${window.location.pathname}`,
    ssoUrl: 'https://YOUR_IDP_DOMAIN/sso/saml',
    relayState: window.location.origin,
    nameIdPolicy: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  };

  samlRequestXml = '';
  samlRedirectUrl = '';
  samlResponse: SamlResponseSummary | null = null;

  constructor(private readonly sso: SsoService) {}

  ngOnInit(): void {
    const oidcParams = this.sso.getOidcCallbackParams(window.location.search);

    if (oidcParams.error) {
      this.error = `OIDC error: ${oidcParams.error}`;
      this.status = 'The identity provider returned an error.';
    } else if (oidcParams.code && oidcParams.state) {
      void this.completeOidcLogin(oidcParams.code, oidcParams.state);
    }

    const samlResponse = this.sso.readSamlResponseFromUrl(window.location.search);
    if (samlResponse.decodedXml) {
      this.activeTab = 'saml';
      this.samlResponse = samlResponse;
      this.status = 'SAML response decoded from the callback URL.';
    }

    this.previewSamlRequest();
  }

  async discoverOidc(): Promise<void> {
    this.run(async () => {
      const metadata = await this.sso.discoverOidc(this.oidcConfig.issuer);
      this.oidcConfig = { ...this.oidcConfig, ...metadata };
      this.status = 'OIDC discovery metadata loaded.';
    });
  }

  async startOidcLogin(): Promise<void> {
    this.run(async () => {
      const authorizationUrl = await this.sso.createOidcAuthorizationUrl(this.oidcConfig);
      window.location.assign(authorizationUrl);
    });
  }

  async completeOidcLogin(code: string, state: string): Promise<void> {
    this.run(async () => {
      this.oidcTokens = await this.sso.exchangeOidcCode(this.oidcConfig, code, state);
      this.oidcIdTokenClaims = this.oidcTokens.id_token ? this.sso.decodeJwt(this.oidcTokens.id_token) : null;
      this.status = 'OIDC token exchange completed.';
      window.history.replaceState({}, document.title, window.location.pathname);
    });
  }

  async loadUserInfo(): Promise<void> {
    if (!this.oidcTokens?.access_token) {
      this.error = 'No access token is available yet.';
      return;
    }

    this.run(async () => {
      this.oidcUserInfo = await this.sso.fetchUserInfo(this.oidcConfig, this.oidcTokens?.access_token ?? '');
      this.status = 'UserInfo loaded.';
    });
  }

  clearOidc(): void {
    this.sso.clearOidcSession();
    this.oidcTokens = null;
    this.oidcIdTokenClaims = null;
    this.oidcUserInfo = null;
    this.error = '';
    this.status = 'OIDC session data cleared.';
  }

  previewSamlRequest(): void {
    this.samlRequestXml = this.sso.createSamlAuthnRequest(this.samlConfig);
    this.samlRedirectUrl = this.sso.createSamlRedirectUrl(this.samlConfig);
  }

  launchSamlPost(): void {
    this.sso.launchSamlPostBinding(this.samlConfig);
  }

  launchSamlRedirect(): void {
    window.location.assign(this.samlRedirectUrl);
  }

  private run(action: () => Promise<void>): void {
    this.busy = true;
    this.error = '';

    action()
      .catch((error: unknown) => {
        this.error = error instanceof Error ? error.message : 'Unexpected error';
      })
      .finally(() => {
        this.busy = false;
      });
  }
}
