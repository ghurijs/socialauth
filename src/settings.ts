import { tryGetContext } from '@ghuri/core'

/** Credentials of one provider app, as in settings (`PROVIDERS.github.APP`) or a `SocialApp` row. */
export interface AppSettings {
  clientId: string
  secret?: string
  key?: string
  /** For `openid_connect`: the id used in URLs (`/accounts/okta/login/`). */
  providerId?: string
  name?: string
  /** Provider-specific settings (`serverUrl` for OpenID Connect, `tenant` for Microsoft…). */
  settings?: Record<string, unknown>
}

export interface ProviderSettings {
  APP?: AppSettings
  /** Several apps of one provider (`openid_connect`). */
  APPS?: AppSettings[]
  SCOPE?: string[]
  AUTH_PARAMS?: Record<string, string>
  /** Override whether this provider's emails count as verified. */
  VERIFIED_EMAIL?: boolean
  [key: string]: unknown
}

export interface SocialAccountSettings {
  PROVIDERS?: Record<string, ProviderSettings>
  ADAPTER?: new () => import('./adapter').SocialAccountAdapter
  AUTO_SIGNUP?: boolean
  EMAIL_AUTHENTICATION?: boolean
  EMAIL_REQUIRED?: boolean
  LOGIN_ON_GET?: boolean
  STORE_TOKENS?: boolean
  LOGIN_RESPONSE?: 'session' | 'jwt'
  FRONTEND_URL?: string
  /** Where browser flows go on errors (default `LOGIN_URL`), with `?error=`. */
  LOGIN_ERROR_URL?: string
}

export interface ResolvedSocialSettings {
  providers: Record<string, ProviderSettings>
  adapter?: new () => import('./adapter').SocialAccountAdapter
  autoSignup: boolean
  emailAuthentication: boolean
  emailRequired: boolean
  loginOnGet: boolean
  storeTokens: boolean
  loginResponse: 'session' | 'jwt'
  frontendUrl?: string
  loginErrorUrl: string
}

export function socialSettings(): ResolvedSocialSettings {
  const settings = (tryGetContext()?.settings ?? {}) as Record<string, unknown>
  const s = (settings.SOCIALACCOUNT ?? {}) as SocialAccountSettings
  return {
    providers: s.PROVIDERS ?? {},
    adapter: s.ADAPTER,
    autoSignup: s.AUTO_SIGNUP ?? true,
    emailAuthentication: s.EMAIL_AUTHENTICATION ?? false,
    emailRequired: s.EMAIL_REQUIRED ?? false,
    loginOnGet: s.LOGIN_ON_GET ?? false,
    storeTokens: s.STORE_TOKENS ?? false,
    loginResponse: s.LOGIN_RESPONSE ?? 'session',
    frontendUrl: s.FRONTEND_URL,
    loginErrorUrl: s.LOGIN_ERROR_URL ?? (settings.LOGIN_URL as string | undefined) ?? '/accounts/login/',
  }
}
