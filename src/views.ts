// URLs and views: providers list, login start, callback, native tokens, SPA code exchange, signup, connections.
import { getUserModel, readData, tokenPairForUser } from '@ghuri/auth'
import {
  csrfExempt,
  escapeHtml,
  getCsrfToken,
  getUser,
  path,
  reverse,
  urlpatterns,
  type ViewFunction,
  wantsJson,
} from '@ghuri/core'
import { type OAuthTokens, type Profile, userInfo } from '@ghuri/oauth'
import type { Context } from 'hono'
import { ImmediateResponse } from './adapter'
import {
  buildLogin,
  completeSocialLogin,
  errorResponse,
  expirePendingSignup,
  type Mode,
  type Process,
  readPendingSignup,
  redeemLoginCode,
  SocialAuthError,
  signup,
} from './login'
import { SocialAccount } from './models'
import { configuredProviders, type ResolvedProvider, resolveProvider } from './resolve'
import { socialSettings } from './settings'
import { socialAccountRemoved } from './signals'

function page(title: string, body: string, status = 200): Response {
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem}button{font:inherit;padding:.5rem 1rem;cursor:pointer}input{font:inherit;width:100%;padding:.4rem;margin:.2rem 0 .8rem;box-sizing:border-box}.err{color:#b91c1c}</style></head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`
  return new Response(html, { status, headers: { 'content-type': 'text/html; charset=utf-8' } })
}

function csrfInput(c: Context): string {
  try {
    return `<input type="hidden" name="csrfmiddlewaretoken" value="${escapeHtml(getCsrfToken(c))}">`
  } catch {
    return ''
  }
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v ? v : undefined
}

async function provider(c: Context): Promise<ResolvedProvider> {
  const key = c.req.param('provider') ?? ''
  const resolved = await resolveProvider(key)
  if (!resolved)
    throw new SocialAuthError(`Unknown or unconfigured provider '${key}'.`, 404, 'unknown_provider')
  return resolved
}

function strategyFor(c: Context, resolved: ResolvedProvider) {
  const callbackURL = c.req.path.replace(/login\/(callback\/)?$/, 'login/callback/')
  const override = (globalThis as any)[Symbol.for('ghuri.socialauth.testStrategy')] as
    | ((key: string, callbackURL: string) => import('@ghuri/oauth').Strategy | undefined)
    | undefined
  const fake = override?.(resolved.key, callbackURL)
  if (fake) return fake
  return resolved.provider.createStrategy({
    key: resolved.key,
    app: resolved.app,
    settings: resolved.settings,
    callbackURL,
    // The social flow decides what happens next; the strategy only has to succeed.
    verify: async () => ({ socialLogin: true }),
  })
}

/** Run a handler, turning SocialAuthError / ImmediateResponse into responses. */
function guarded(mode: Mode | ((c: Context) => Mode), fn: (c: Context) => Promise<Response>): ViewFunction {
  return async (c) => {
    const m = typeof mode === 'function' ? mode(c) : mode
    try {
      return await fn(c)
    } catch (err) {
      if (err instanceof ImmediateResponse) return err.response
      if (err instanceof SocialAuthError) return errorResponse(c, err, c.req.param('provider') ?? '', m)
      throw err
    }
  }
}

/** JSON only: refuses cross-site form posts to the CSRF-exempt API endpoints (they can't send JSON). */
function requireJson(c: Context): void {
  if (!(c.req.header('content-type') ?? '').includes('application/json')) {
    throw new SocialAuthError('Send a JSON body (Content-Type: application/json).', 415, 'json_required')
  }
}

// ---- views ----

/** `GET providers/`: configured providers with their login URLs (for SPA buttons). */
export const providersView: ViewFunction = async (c) => {
  const list = await configuredProviders()
  return c.json({
    providers: list.map((p) => ({
      id: p.key,
      name: p.app.name ?? p.provider.name,
      provider: p.provider.id,
      loginUrl: reverse('socialaccount_login', { provider: p.key }),
      nativeTokenUrl: reverse('socialaccount_native_token', { provider: p.key }),
    })),
  })
}

/** `<provider>/login/`: POST starts the flow; GET confirms first (unless LOGIN_ON_GET). */
export const loginView: ViewFunction = guarded('browser', async (c) => {
  const resolved = await provider(c)
  const s = socialSettings()
  if (c.req.method === 'GET' && !s.loginOnGet) {
    if (wantsJson(c)) return c.json({ detail: 'POST to this URL to log in.', method: 'POST' }, 405)
    const action = escapeHtml(c.req.url.replace(/^[a-z]+:\/\/[^/]+/i, ''))
    const name = escapeHtml(resolved.app.name ?? resolved.provider.name)
    return page(
      `Continue with ${resolved.app.name ?? resolved.provider.name}`,
      `<p>You are about to log in with ${name}.</p><form method="post" action="${action}">${csrfInput(c)}<button type="submit">Continue</button></form>`,
    )
  }
  if (c.req.method !== 'GET' && c.req.method !== 'POST') return c.text('Method not allowed', 405)
  const data = c.req.method === 'POST' ? await readData(c) : {}
  const process = (str(data.process) ?? c.req.query('process')) === 'connect' ? 'connect' : 'login'
  if (process === 'connect' && !getUser(c).isAuthenticated) {
    throw new SocialAuthError('Log in before connecting an account.', 401, 'login_required')
  }
  const result = await strategyFor(c, resolved).authenticate(c, {
    next: str(data.next) ?? c.req.query('next'),
    state: { process },
  })
  if (result.type === 'redirect') return c.redirect(result.url, 302)
  if (result.type === 'error') throw result.error
  throw new SocialAuthError(
    result.type === 'fail' ? (result.message ?? 'Login failed.') : 'Login failed.',
    400,
  )
})

/** `<provider>/login/callback/`: the provider sends the browser back here. */
export const callbackView: ViewFunction = guarded('browser', async (c) => {
  const resolved = await provider(c)
  if (!c.req.query('code') && !c.req.query('error')) {
    throw new SocialAuthError('The provider did not send an authorization code.', 400, 'missing_code')
  }
  const result = await strategyFor(c, resolved).authenticate(c, {})
  if (result.type === 'error') throw result.error
  if (result.type !== 'success') {
    throw new SocialAuthError(
      result.type === 'fail' ? (result.message ?? 'Login failed.') : 'Login failed.',
      401,
    )
  }
  const info = result.info as {
    profile: Profile
    tokens: OAuthTokens
    next?: string
    state?: { process?: Process }
  }
  const login = buildLogin(resolved, info.profile, {
    tokens: info.tokens,
    next: info.next,
    process: info.state?.process === 'connect' ? 'connect' : 'login',
  })
  return completeSocialLogin(c, login, 'browser')
})

/**
 * `POST <provider>/token/` `{ id_token }` or `{ access_token }`: log in with a token a native app got from the
 * provider's SDK. The token is checked against our client id(s) before it is trusted.
 */
export const nativeTokenView: ViewFunction = csrfExempt(
  guarded('api', async (c) => {
    if (c.req.method !== 'POST') return c.json({ detail: 'Method not allowed' }, 405)
    requireJson(c)
    const resolved = await provider(c)
    const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
    const idToken = str(body.id_token)
    const accessToken = str(body.access_token)
    if (!idToken && !accessToken)
      throw new SocialAuthError('Send id_token or access_token.', 400, 'missing_token')
    let profile: Profile
    try {
      profile = await resolved.provider.verifyNativeToken(
        {
          key: resolved.key,
          app: resolved.app,
          settings: resolved.settings,
          callbackURL: '/',
          verify: async () => null,
        },
        { idToken, accessToken },
      )
    } catch (err) {
      throw new SocialAuthError((err as Error).message || 'Invalid token.', 401, 'invalid_token')
    }
    const login = buildLogin(resolved, profile, {
      tokens: accessToken ? { accessToken, raw: {} } : undefined,
      process: str(body.process) === 'connect' ? 'connect' : 'login',
    })
    return completeSocialLogin(c, login, 'api')
  }),
)

/** `POST token/` `{ code }`: exchange the one-time code from an SPA redirect for a JWT pair. */
export const tokenExchangeView: ViewFunction = csrfExempt(
  guarded('api', async (c) => {
    if (c.req.method !== 'POST') return c.json({ detail: 'Method not allowed' }, 405)
    requireJson(c)
    const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>
    const user = str(body.code) ? await redeemLoginCode(str(body.code)!) : null
    if (!user)
      throw new SocialAuthError('This login code is invalid, expired or already used.', 400, 'invalid_code')
    return c.json({ ...(await tokenPairForUser(user)), user: userInfo(user) })
  }),
)

/** `signup/`: finish a social signup that needs a username or email. */
export const signupView: ViewFunction = guarded(
  (c) => (wantsJson(c) ? 'api' : 'browser'),
  async (c) => {
    const pending = await readPendingSignup(c)
    if (!pending)
      throw new SocialAuthError('There is no social signup in progress.', 400, 'no_pending_signup')
    const resolved = await resolveProvider(pending.key)
    if (!resolved) throw new SocialAuthError('The provider is no longer configured.', 400, 'unknown_provider')
    const login = buildLogin(resolved, pending.profile, { tokens: pending.tokens, next: pending.next })
    const User = getUserModel()
    const uf = User.USERNAME_FIELD
    const ef = User.EMAIL_FIELD
    const json = wantsJson(c)
    const render = (values: Record<string, string>, errors: Record<string, string[]> = {}, status = 200) => {
      if (json) {
        return c.json(
          {
            provider: pending.key,
            profile: {
              email: pending.profile.email,
              username: pending.profile.username,
              name: pending.profile.name,
            },
            fields: [...new Set([uf, ef])],
            errors,
          },
          status as 200,
        )
      }
      const field = (name: string, label: string) =>
        `<label>${escapeHtml(label)}<input name="${escapeHtml(name)}" value="${escapeHtml(values[name] ?? '')}"></label>${(errors[name] ?? []).map((e) => `<p class="err">${escapeHtml(e)}</p>`).join('')}`
      const fields = uf === ef ? field(ef, 'Email') : field(uf, 'Username') + field(ef, 'Email')
      return page(
        'Finish signing up',
        `<p>You are signing up with ${escapeHtml(resolved.app.name ?? resolved.provider.name)}.</p><form method="post">${csrfInput(c)}${fields}<button type="submit">Sign up</button></form>`,
        status,
      )
    }
    if (c.req.method === 'GET') {
      return render({ [uf]: pending.profile.username ?? '', [ef]: pending.profile.email ?? '' })
    }
    const data = await readData(c)
    const values = { [uf]: String(data[uf] ?? ''), [ef]: String(data[ef] ?? '') }
    // An address the user typed is not verified by the provider.
    if (values[ef] && values[ef].toLowerCase() !== (pending.profile.email ?? '').toLowerCase())
      login.emailVerified = false
    const result = await signup(
      c,
      login,
      { username: values[uf], email: values[ef] },
      json ? 'api' : 'browser',
    )
    if (result instanceof Response) return expirePendingSignup(c, result)
    return render(values, result, 400)
  },
)

/** `connections/`: list the user's social accounts (GET) and disconnect one (POST `{ account }`). */
export const connectionsView: ViewFunction = guarded(
  (c) => (wantsJson(c) ? 'api' : 'browser'),
  async (c) => {
    const user = getUser(c)
    if (!user.isAuthenticated)
      throw new SocialAuthError('Log in to manage your connected accounts.', 401, 'login_required')
    const accounts = await SocialAccount.objects.filter({ user: user.pk } as any).orderBy('provider', 'id')
    if (c.req.method === 'POST') {
      const data = await readData(c)
      const id = String(data.account ?? '')
      const account = accounts.find((a) => String(a.pk) === id)
      if (!account) throw new SocialAuthError('No such connected account.', 404, 'not_found')
      const User = getUserModel()
      const full = await User.objects.filter({ pk: user.pk } as any).first()
      if (
        accounts.length === 1 &&
        full &&
        typeof (full as any).hasUsablePassword === 'function' &&
        !(full as any).hasUsablePassword()
      ) {
        throw new SocialAuthError(
          'Set a password before disconnecting your last connected account.',
          400,
          'last_login_method',
        )
      }
      await account.delete()
      await socialAccountRemoved.send(SocialAccount, { c, account })
      if (wantsJson(c)) return c.json({ disconnected: id })
      return c.redirect(c.req.path, 302)
    }
    const list = accounts.map((a) => ({
      id: a.pk,
      provider: a.provider,
      uid: a.uid,
      lastLogin: a.lastLogin,
      dateJoined: a.dateJoined,
    }))
    if (wantsJson(c)) return c.json({ accounts: list })
    const rows = list
      .map(
        (a) =>
          `<li>${escapeHtml(a.provider)} <form method="post" style="display:inline">${csrfInput(c)}<input type="hidden" name="account" value="${escapeHtml(a.id)}"><button type="submit">Disconnect</button></form></li>`,
      )
      .join('')
    return page('Connected accounts', rows ? `<ul>${rows}</ul>` : '<p>No connected accounts.</p>')
  },
)

/**
 * `path('accounts/', include(socialUrls))` → `providers/`, `token/`, `signup/`, `connections/`,
 * `<provider>/login/`, `<provider>/login/callback/`, `<provider>/token/`.
 */
export const socialUrls = urlpatterns(undefined, [
  path('providers/', providersView, { name: 'socialaccount_providers' }),
  path('token/', tokenExchangeView, { name: 'socialaccount_token_exchange' }),
  path('signup/', signupView, { name: 'socialaccount_signup' }),
  path('connections/', connectionsView, { name: 'socialaccount_connections' }),
  path('<str:provider>/login/', loginView, { name: 'socialaccount_login' }),
  path('<str:provider>/login/callback/', callbackView, { name: 'socialaccount_callback' }),
  path('<str:provider>/token/', nativeTokenView, { name: 'socialaccount_native_token' }),
])
