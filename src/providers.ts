// The provider catalog: each provider turns app credentials into an @ghuri/oauth strategy and knows how far to
// trust its profile (is the email verified?).

import { ImproperlyConfigured } from '@ghuri/core'
import {
  getJson,
  OAuth2Strategy,
  OAuthError,
  OIDCStrategy,
  type Profile,
  profileFromClaims,
  providerFetch,
  readBody,
  type VerifyFunction,
} from '@ghuri/oauth'
import type { AppSettings, ProviderSettings } from './settings'

export interface StrategyContext {
  /** The id used in URLs and stored on `SocialAccount.provider` (`github`, or an OIDC app's `providerId`). */
  key: string
  app: AppSettings
  settings: ProviderSettings
  callbackURL: string
  verify: VerifyFunction
}

export abstract class Provider {
  abstract readonly id: string
  abstract readonly name: string
  /** Several apps per provider, each with its own `providerId` (OpenID Connect). */
  readonly multipleApps: boolean = false
  /** Default scopes when `SCOPE` is not set. */
  readonly defaultScope: string[] = []

  abstract createStrategy(ctx: StrategyContext): OAuth2Strategy

  scope(settings: ProviderSettings): string[] {
    return settings.SCOPE ?? this.defaultScope
  }

  /** May this provider's email be trusted to belong to the user? */
  emailVerified(profile: Profile, settings: ProviderSettings): boolean {
    if (settings.VERIFIED_EMAIL !== undefined) return settings.VERIFIED_EMAIL && !!profile.email
    return profile.emailVerified === true && !!profile.email
  }

  /**
   * Native / mobile login: verify a token the app obtained with the provider's own SDK and return the profile.
   * The token must have been issued to one of our client ids. Default: ID tokens of OpenID Connect providers.
   */
  async verifyNativeToken(
    ctx: StrategyContext,
    tokens: { accessToken?: string; idToken?: string },
  ): Promise<Profile> {
    const strategy = this.createStrategy(ctx)
    if (!(strategy instanceof OIDCStrategy) || !tokens.idToken) {
      throw new OAuthError(`${this.name} login with a native token needs an id_token.`, 'unsupported')
    }
    const audiences = [ctx.app.clientId, ...((ctx.app.settings?.audiences as string[] | undefined) ?? [])]
    let claims: Record<string, any> | undefined
    let lastError: unknown
    for (const aud of audiences) {
      try {
        const s = this.createStrategy({ ...ctx, app: { ...ctx.app, clientId: aud } }) as OIDCStrategy
        claims = await s.validateIdToken(tokens.idToken)
        break
      } catch (err) {
        lastError = err
      }
    }
    if (!claims)
      throw lastError instanceof Error
        ? new OAuthError(lastError.message, 'invalid_token')
        : new OAuthError('Invalid ID token.')
    return this.profileFromClaims(ctx.key, claims)
  }

  profileFromClaims(key: string, claims: Record<string, any>): Profile {
    return profileFromClaims(key, claims)
  }
}

function common(ctx: StrategyContext, provider: Provider) {
  return {
    name: ctx.key,
    clientId: ctx.app.clientId,
    clientSecret: ctx.app.secret,
    callbackURL: ctx.callbackURL,
    scope: provider.scope(ctx.settings),
    authorizationParams: ctx.settings.AUTH_PARAMS,
  }
}

/** An OIDC strategy whose profile goes through the provider's own claim mapping. */
function oidc(
  ctx: StrategyContext,
  provider: Provider,
  issuer: string,
  extra: Record<string, unknown> = {},
): OIDCStrategy {
  return new OIDCStrategy(
    {
      ...common(ctx, provider),
      issuer,
      profile: async (tokens) =>
        provider.profileFromClaims(ctx.key, (tokens.raw as { claims: Record<string, any> }).claims),
      ...extra,
    },
    ctx.verify,
  )
}

// ---- GitHub ----

export class GitHubProvider extends Provider {
  readonly id = 'github'
  readonly name = 'GitHub'
  override readonly defaultScope = ['read:user', 'user:email']

  private api(ctx: StrategyContext): string {
    return String(ctx.app.settings?.apiUrl ?? 'https://api.github.com').replace(/\/+$/, '')
  }

  createStrategy(ctx: StrategyContext): OAuth2Strategy {
    const web = String(ctx.app.settings?.webUrl ?? 'https://github.com').replace(/\/+$/, '')
    const api = this.api(ctx)
    return new OAuth2Strategy(
      {
        ...common(ctx, this),
        authorizationURL: `${web}/login/oauth/authorize`,
        tokenURL: `${web}/login/oauth/access_token`,
        profile: async (_tokens, p) => this.profile(ctx.key, api, (url) => p.getJsonAuthed(url)),
      },
      ctx.verify,
    )
  }

  private async profile(key: string, api: string, get: (url: string) => Promise<any>): Promise<Profile> {
    const user = await get(`${api}/user`)
    let email: string | undefined = user.email ?? undefined
    let verified = false
    try {
      const emails = (await get(`${api}/user/emails`)) as unknown as Array<{
        email: string
        primary: boolean
        verified: boolean
      }>
      const list = Array.isArray(emails) ? emails : []
      const primary = list.find((e) => e.primary && e.verified) ?? list.find((e) => e.verified)
      if (primary) {
        email = primary.email
        verified = true
      }
    } catch {
      // no user:email scope
    }
    return {
      provider: key,
      id: String(user.id),
      username: user.login,
      name: user.name ?? undefined,
      email,
      emailVerified: verified,
      avatarUrl: user.avatar_url,
      raw: user,
    }
  }

  /** Checks with GitHub that the token belongs to our OAuth app (`POST /applications/{client_id}/token`). */
  override async verifyNativeToken(ctx: StrategyContext, tokens: { accessToken?: string }): Promise<Profile> {
    if (!tokens.accessToken)
      throw new OAuthError('GitHub login with a native token needs an access_token.', 'unsupported')
    const api = this.api(ctx)
    const res = await providerFetch(`${api}/applications/${encodeURIComponent(ctx.app.clientId)}/token`, {
      method: 'POST',
      headers: {
        authorization: `Basic ${btoa(`${ctx.app.clientId}:${ctx.app.secret ?? ''}`)}`,
        accept: 'application/vnd.github+json',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ access_token: tokens.accessToken }),
    })
    if (!res.ok) throw new OAuthError('GitHub did not accept the access token for this app.', 'invalid_token')
    const headers = { authorization: `Bearer ${tokens.accessToken}` }
    return this.profile(ctx.key, api, (url) => getJson(url, { headers }))
  }
}

// ---- Google ----

export class GoogleProvider extends Provider {
  readonly id = 'google'
  readonly name = 'Google'
  override readonly defaultScope = ['openid', 'email', 'profile']

  createStrategy(ctx: StrategyContext): OAuth2Strategy {
    return oidc(ctx, this, 'https://accounts.google.com')
  }
}

// ---- Facebook ----

export class FacebookProvider extends Provider {
  readonly id = 'facebook'
  readonly name = 'Facebook'
  override readonly defaultScope = ['email', 'public_profile']

  private graph(ctx: StrategyContext): string {
    return `https://graph.facebook.com/${String(ctx.settings.VERSION ?? ctx.app.settings?.version ?? 'v21.0')}`
  }

  createStrategy(ctx: StrategyContext): OAuth2Strategy {
    const version = String(ctx.settings.VERSION ?? ctx.app.settings?.version ?? 'v21.0')
    const graph = this.graph(ctx)
    return new OAuth2Strategy(
      {
        ...common(ctx, this),
        scopeSeparator: ',',
        authorizationURL: `https://www.facebook.com/${version}/dialog/oauth`,
        tokenURL: `${graph}/oauth/access_token`,
        profile: async (_t, p) =>
          this.profile(
            ctx.key,
            await p.getJsonAuthed(`${graph}/me?fields=id,name,email,first_name,last_name,picture`),
          ),
      },
      ctx.verify,
    )
  }

  private profile(key: string, me: Record<string, any>): Profile {
    return {
      provider: key,
      id: String(me.id),
      name: me.name,
      firstName: me.first_name,
      lastName: me.last_name,
      email: me.email,
      // Facebook does not say whether the address was confirmed: unverified unless VERIFIED_EMAIL.
      emailVerified: false,
      avatarUrl: me.picture?.data?.url,
      raw: me,
    }
  }

  /** Checks the token with `debug_token` (issued to our app id) before trusting it. */
  override async verifyNativeToken(ctx: StrategyContext, tokens: { accessToken?: string }): Promise<Profile> {
    if (!tokens.accessToken)
      throw new OAuthError('Facebook login with a native token needs an access_token.', 'unsupported')
    const graph = this.graph(ctx)
    const appToken = `${ctx.app.clientId}|${ctx.app.secret ?? ''}`
    const debug = await getJson(
      `${graph}/debug_token?input_token=${encodeURIComponent(tokens.accessToken)}&access_token=${encodeURIComponent(appToken)}`,
    )
    if (!debug.data?.is_valid || String(debug.data.app_id) !== ctx.app.clientId) {
      throw new OAuthError('The Facebook token was not issued to this app.', 'invalid_token')
    }
    const me = await getJson(`${graph}/me?fields=id,name,email,first_name,last_name,picture`, {
      headers: { authorization: `Bearer ${tokens.accessToken}` },
    })
    return this.profile(ctx.key, me)
  }
}

// ---- Microsoft (Entra ID) ----

export class MicrosoftProvider extends Provider {
  readonly id = 'microsoft'
  readonly name = 'Microsoft'
  override readonly defaultScope = ['openid', 'email', 'profile', 'User.Read']

  createStrategy(ctx: StrategyContext): OAuth2Strategy {
    const tenant = String(ctx.app.settings?.tenant ?? ctx.settings.TENANT ?? 'common')
    const multi = ['common', 'organizations', 'consumers'].includes(tenant)
    return oidc(ctx, this, `https://login.microsoftonline.com/${tenant}/v2.0`, {
      // Multi-tenant endpoints publish `{tenantid}` in their issuer; accept any tenant's issuer.
      issuerValidation: multi
        ? (iss: string) => /^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/v2\.0$/.test(iss)
        : undefined,
      fetchUserInfo: false,
    })
  }

  override profileFromClaims(key: string, claims: Record<string, any>): Profile {
    const p = profileFromClaims(key, claims)
    // Entra ID emails are not verified by Microsoft (tenants can set any address): never trust them by default.
    return { ...p, id: String(claims.oid ?? claims.sub), emailVerified: false }
  }

  override emailVerified(profile: Profile, settings: ProviderSettings): boolean {
    return settings.VERIFIED_EMAIL === true && !!profile.email
  }
}

// ---- Discord ----

export class DiscordProvider extends Provider {
  readonly id = 'discord'
  readonly name = 'Discord'
  override readonly defaultScope = ['identify', 'email']

  createStrategy(ctx: StrategyContext): OAuth2Strategy {
    return new OAuth2Strategy(
      {
        ...common(ctx, this),
        authorizationURL: 'https://discord.com/oauth2/authorize',
        tokenURL: 'https://discord.com/api/oauth2/token',
        profile: async (_t, p) => {
          const me = await p.getJsonAuthed('https://discord.com/api/users/@me')
          return {
            provider: ctx.key,
            id: String(me.id),
            username: me.username,
            name: me.global_name ?? me.username,
            email: me.email ?? undefined,
            emailVerified: me.verified === true,
            avatarUrl: me.avatar ? `https://cdn.discordapp.com/avatars/${me.id}/${me.avatar}.png` : undefined,
            raw: me,
          }
        },
      },
      ctx.verify,
    )
  }

  override async verifyNativeToken(): Promise<Profile> {
    throw new OAuthError(
      'Discord tokens cannot be checked against a client id; use the redirect flow.',
      'unsupported',
    )
  }
}

// ---- GitLab (gitlab.com or self-hosted) ----

export class GitLabProvider extends Provider {
  readonly id = 'gitlab'
  readonly name = 'GitLab'
  override readonly defaultScope = ['openid', 'email', 'profile']

  createStrategy(ctx: StrategyContext): OAuth2Strategy {
    const url = String(ctx.app.settings?.url ?? ctx.settings.GITLAB_URL ?? 'https://gitlab.com').replace(
      /\/+$/,
      '',
    )
    return oidc(ctx, this, url)
  }

  override profileFromClaims(key: string, claims: Record<string, any>): Profile {
    return { ...profileFromClaims(key, claims), username: claims.nickname ?? claims.preferred_username }
  }
}

// ---- Any OpenID Connect issuer ----

export class OpenIDConnectProvider extends Provider {
  readonly id = 'openid_connect'
  readonly name = 'OpenID Connect'
  override readonly multipleApps = true
  override readonly defaultScope = ['openid', 'email', 'profile']

  createStrategy(ctx: StrategyContext): OAuth2Strategy {
    const issuer = ctx.app.settings?.serverUrl ?? ctx.app.settings?.server_url
    if (typeof issuer !== 'string') {
      throw new ImproperlyConfigured(
        `The OpenID Connect app '${ctx.key}' needs settings.serverUrl (the issuer).`,
      )
    }
    return oidc(ctx, this, issuer)
  }
}

// ---- registry ----

const KEY = Symbol.for('ghuri.socialauth.providers')
const registry: Map<string, Provider> = (() => {
  const g = globalThis as any
  if (!g[KEY]) {
    const m = new Map<string, Provider>()
    for (const p of [
      new GitHubProvider(),
      new GoogleProvider(),
      new FacebookProvider(),
      new MicrosoftProvider(),
      new DiscordProvider(),
      new GitLabProvider(),
      new OpenIDConnectProvider(),
    ]) {
      m.set(p.id, p)
    }
    g[KEY] = m
  }
  return g[KEY]
})()

/** Add (or replace) a provider: `registerProvider(new MyProvider())`. */
export function registerProvider(provider: Provider): void {
  registry.set(provider.id, provider)
}

export function getProvider(id: string): Provider | undefined {
  return registry.get(id)
}

export function allProviders(): Provider[] {
  return [...registry.values()]
}

/** Used by provider subclasses that need raw responses. */
export { readBody }
