// What happens after the provider answered: find or link the account, sign up, log in, respond.
import { login as authLogin, getUserModel, isSafeRedirect, tokenPairForUser } from '@ghuri/auth'
import { cache, getHost, getUser, isSecure, resolveUrl, reverse, tryGetContext } from '@ghuri/core'
import {
  loginBackendName,
  type OAuthTokens,
  type Profile,
  randomToken,
  seal,
  unseal,
  userInfo,
} from '@ghuri/oauth'
import type { Context } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { getAdapter, type SignupData } from './adapter'
import { SocialAccount } from './models'
import type { ResolvedProvider } from './resolve'
import { socialSettings } from './settings'
import { preSocialLogin, socialAccountAdded, socialAccountUpdated } from './signals'
import { storeTokens } from './tokens'

export type Process = 'login' | 'connect'
/** `browser`: redirects (the OAuth callback); `api`: JSON (native tokens, SPA calls). */
export type Mode = 'browser' | 'api'

export interface SocialLogin extends ResolvedProvider {
  profile: Profile
  tokens?: OAuthTokens
  /** Whether the provider vouches for `profile.email`. */
  emailVerified: boolean
  process: Process
  next?: string
}

export class SocialAuthError extends Error {
  constructor(
    message: string,
    readonly status = 400,
    readonly code = 'social_login_failed',
  ) {
    super(message)
  }
}

export function buildLogin(
  resolved: ResolvedProvider,
  profile: Profile,
  opts: { tokens?: OAuthTokens; process?: Process; next?: string },
): SocialLogin {
  return {
    ...resolved,
    profile: { ...profile, provider: resolved.key },
    tokens: opts.tokens,
    emailVerified: resolved.provider.emailVerified(profile, resolved.settings),
    process: opts.process ?? 'login',
    next: opts.next,
  }
}

// ---- responses ----

function loginRedirectUrl(): string {
  return resolveUrl(
    (tryGetContext()?.settings.LOGIN_REDIRECT_URL as string | undefined) ?? '/accounts/profile/',
  )
}

const CODE_PURPOSE = 'socialauth-code'
const CODE_TTL = 60

/** A one-time code an SPA exchanges for a JWT pair at `token/` (tokens never travel in URLs). */
export async function makeLoginCode(user: any): Promise<string> {
  return seal(
    JSON.stringify({
      uid: String(user.pk),
      exp: Math.floor(Date.now() / 1000) + CODE_TTL,
      jti: randomToken(12),
    }),
    CODE_PURPOSE,
  )
}

/** The user of a login code, once (replays are refused while the cache remembers the code). */
export async function redeemLoginCode(code: string): Promise<any | null> {
  const raw = await unseal(code, CODE_PURPOSE)
  if (!raw) return null
  let data: { uid: string; exp: number; jti: string }
  try {
    data = JSON.parse(raw)
  } catch {
    return null
  }
  if (!data.exp || data.exp < Date.now() / 1000) return null
  const key = `ghuri:socialauth:code:${data.jti}`
  try {
    if (await cache.get(key)) return null
    await cache.set(key, 1, CODE_TTL * 2)
  } catch {
    // no cache configured: the 60-second expiry is the only replay limit
  }
  const User = getUserModel()
  const user = await User.objects.filter({ pk: User._meta.pk.toPython(data.uid) } as any).first()
  return user && (user as any).isActive !== false ? user : null
}

/** Log the user in and answer for the mode and `LOGIN_RESPONSE`. */
export async function finishLogin(c: Context, user: any, login: SocialLogin, mode: Mode): Promise<Response> {
  const s = socialSettings()
  if (user.isActive === false) throw new SocialAuthError('This account is inactive.', 403, 'inactive')
  if (s.loginResponse === 'jwt') {
    if (mode === 'api') return c.json({ ...(await tokenPairForUser(user)), user: userInfo(user) })
    if (!s.frontendUrl)
      throw new SocialAuthError('SOCIALACCOUNT.FRONTEND_URL is required with LOGIN_RESPONSE "jwt".', 500)
    return c.redirect(`${s.frontendUrl}#code=${encodeURIComponent(await makeLoginCode(user))}`, 302)
  }
  await authLogin(c, user, loginBackendName())
  if (mode === 'api') return c.json({ user: userInfo(user) })
  const next = login.next
  return c.redirect(isSafeRedirect(next, [getHost(c)]) ? next : loginRedirectUrl(), 302)
}

/** An error, answered as JSON (api) or a redirect to `LOGIN_ERROR_URL` / the frontend (browser). */
export async function errorResponse(
  c: Context,
  err: SocialAuthError,
  provider: string,
  mode: Mode,
): Promise<Response> {
  const custom = await getAdapter().authenticationError(c, { provider, message: err.message, code: err.code })
  if (custom) return custom
  if (mode === 'api') return c.json({ detail: err.message, code: err.code }, err.status as 400)
  const s = socialSettings()
  if (s.loginResponse === 'jwt' && s.frontendUrl) {
    return c.redirect(`${s.frontendUrl}#error=${encodeURIComponent(err.message)}`, 302)
  }
  const url = new URL(s.loginErrorUrl, 'http://x')
  url.searchParams.set('error', err.message)
  return c.redirect(`${url.pathname}${url.search}`, 302)
}

// ---- pending signup (when the form is needed) ----

const SIGNUP_COOKIE = 'ghuri_social_signup'
const SIGNUP_PURPOSE = 'socialauth-signup'
const SIGNUP_TTL = 600

export interface PendingSignup {
  key: string
  profile: Profile
  tokens?: OAuthTokens
  emailVerified: boolean
  next?: string
  createdAt: number
}

export async function savePendingSignup(c: Context, login: SocialLogin): Promise<void> {
  const pending: PendingSignup = {
    key: login.key,
    profile: login.profile,
    tokens: socialSettings().storeTokens ? login.tokens : undefined,
    emailVerified: login.emailVerified,
    next: login.next,
    createdAt: Date.now(),
  }
  setCookie(c, SIGNUP_COOKIE, await seal(JSON.stringify(pending), SIGNUP_PURPOSE), {
    path: '/',
    httpOnly: true,
    secure: isSecure(c),
    sameSite: 'Lax',
    maxAge: SIGNUP_TTL,
  })
}

export async function readPendingSignup(c: Context): Promise<PendingSignup | null> {
  const raw = getCookie(c, SIGNUP_COOKIE)
  if (!raw) return null
  const json = await unseal(raw, SIGNUP_PURPOSE)
  if (!json) return null
  try {
    const p = JSON.parse(json) as PendingSignup
    return Date.now() - p.createdAt <= SIGNUP_TTL * 1000 ? p : null
  } catch {
    return null
  }
}

export function clearPendingSignup(c: Context): void {
  deleteCookie(c, SIGNUP_COOKIE, { path: '/', secure: isSecure(c) })
}

/** Expire the pending-signup cookie on a response that was already built. */
export function expirePendingSignup(c: Context, res: Response): Response {
  res.headers.append(
    'set-cookie',
    `${SIGNUP_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${isSecure(c) ? '; Secure' : ''}`,
  )
  return res
}

// ---- the flow ----

async function emailTaken(email: string, exceptPk?: unknown): Promise<boolean> {
  const User = getUserModel()
  let qs = User.objects.filter({ [`${User.EMAIL_FIELD}__iexact`]: email } as any)
  if (exceptPk !== undefined) qs = qs.exclude({ pk: exceptPk } as any)
  return qs.exists()
}

async function link(c: Context, login: SocialLogin, user: any): Promise<SocialAccount> {
  const account = await SocialAccount.objects.create({
    user,
    provider: login.key,
    uid: login.profile.id,
    extraData: login.profile.raw,
  } as any)
  await storeTokens(login, account)
  await socialAccountAdded.send(SocialAccount, { c, login, account })
  return account
}

/**
 * Create the user from the profile and the (optional) form data, link it, log in. Returns the problems instead
 * when the data is not acceptable.
 */
export async function signup(
  c: Context,
  login: SocialLogin,
  data: SignupData,
  mode: Mode,
): Promise<Response | Record<string, string[]>> {
  const adapter = getAdapter()
  const User = getUserModel()
  const errors: Record<string, string[]> = {}
  const username = (data.username ?? '').trim()
  const email = (data.email ?? '').trim()
  if (User.USERNAME_FIELD !== User.EMAIL_FIELD) {
    if (!username) errors[User.USERNAME_FIELD] = ['This field is required.']
    else if (await User.objects.filter({ [`${User.USERNAME_FIELD}__iexact`]: username } as any).exists()) {
      errors[User.USERNAME_FIELD] = ['A user with that username already exists.']
    }
  }
  if (!email && (socialSettings().emailRequired || User.USERNAME_FIELD === User.EMAIL_FIELD)) {
    errors[User.EMAIL_FIELD] = ['This field is required.']
  } else if (email && (await emailTaken(email))) {
    errors[User.EMAIL_FIELD] = [
      `An account already uses this address. Log in to it first, then connect ${login.provider.name} from your account.`,
    ]
  }
  if (Object.keys(errors).length) return errors
  let user = adapter.newUser(c, login)
  user = adapter.populateUser(c, login, user, {
    username: User.USERNAME_FIELD === User.EMAIL_FIELD ? email : username,
    email: email || undefined,
  })
  user = await adapter.saveUser(c, login, user)
  await link(c, login, user)
  return finishLogin(c, user, login, mode)
}

/** Process a successful provider login (django-allauth's `complete_social_login`). */
export async function completeSocialLogin(c: Context, login: SocialLogin, mode: Mode): Promise<Response> {
  const adapter = getAdapter()
  await preSocialLogin.send(SocialAccount, { c, login })
  await adapter.preSocialLogin(c, login)
  const current = getUser(c)
  const User = getUserModel()

  // 1. A known link.
  const existing = await SocialAccount.objects.filter({ provider: login.key, uid: login.profile.id }).first()
  if (existing) {
    existing.extraData = login.profile.raw
    await existing.save()
    await storeTokens(login, existing)
    await socialAccountUpdated.send(SocialAccount, { c, login, account: existing })
    const userId = (existing as any).userId ?? (existing as any).user_id
    if (login.process === 'connect') {
      if (!current.isAuthenticated)
        throw new SocialAuthError('Log in before connecting an account.', 401, 'login_required')
      if (String(userId) !== String(current.pk)) {
        throw new SocialAuthError(
          `This ${login.provider.name} account is already connected to another user.`,
          409,
          'already_connected',
        )
      }
      return mode === 'api'
        ? c.json({ connected: true })
        : c.redirect(adapter.getConnectRedirectUrl(c, existing), 302)
    }
    const user = await User.objects.filter({ pk: userId } as any).first()
    if (!user) throw new SocialAuthError('The linked user no longer exists.', 401, 'user_missing')
    return finishLogin(c, user, login, mode)
  }

  // 2. Connecting to the logged-in user.
  if (login.process === 'connect') {
    if (!current.isAuthenticated)
      throw new SocialAuthError('Log in before connecting an account.', 401, 'login_required')
    const user = await User.objects.filter({ pk: current.pk } as any).first()
    const account = await link(c, login, user)
    return mode === 'api'
      ? c.json({ connected: true })
      : c.redirect(adapter.getConnectRedirectUrl(c, account), 302)
  }

  // 3. A verified email that belongs to exactly one user.
  const s = socialSettings()
  if (s.emailAuthentication && login.emailVerified && login.profile.email) {
    const matches = await User.objects
      .filter({ [`${User.EMAIL_FIELD}__iexact`]: login.profile.email } as any)
      .limit(2)
    if (matches.length === 1) {
      await link(c, login, matches[0])
      return finishLogin(c, matches[0], login, mode)
    }
  }

  // 4. Sign up.
  if (!(await adapter.isOpenForSignup(c, login))) {
    throw new SocialAuthError('Sign-ups are closed.', 403, 'signup_closed')
  }
  if (await adapter.isAutoSignupAllowed(c, login)) {
    const email =
      login.profile.email && !(await emailTaken(login.profile.email)) ? login.profile.email : undefined
    if (email || (!s.emailRequired && !login.profile.email && User.USERNAME_FIELD !== User.EMAIL_FIELD)) {
      const result = await signup(
        c,
        login,
        {
          username:
            User.USERNAME_FIELD === User.EMAIL_FIELD ? email : await adapter.generateUsername(c, login),
          email,
        },
        mode,
      )
      if (result instanceof Response) return result
    }
  }
  await savePendingSignup(c, login)
  let signupUrl = '/accounts/signup/'
  try {
    signupUrl = reverse('socialaccount_signup')
  } catch {
    // not routed by name
  }
  if (mode === 'api') {
    return c.json({ detail: 'Finish signing up.', code: 'signup_required', signupUrl }, 409)
  }
  return c.redirect(signupUrl, 302)
}
