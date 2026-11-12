// @ghuri/socialauth/testing — run the social login flow in tests without talking to a provider.
import { type Profile, Strategy, type StrategyResult } from '@ghuri/oauth'
import type { Context } from 'hono'

export const TEST_STRATEGY_KEY = Symbol.for('ghuri.socialauth.testStrategy')

/** Pretends to be the provider: start redirects straight to the callback, the callback returns `profile`. */
class FakeProviderStrategy extends Strategy {
  readonly name = 'socialauth-test'
  constructor(
    private readonly profile: Profile,
    private readonly callbackURL: string,
  ) {
    super()
  }
  async authenticate(
    c: Context,
    options: { next?: string; state?: Record<string, string> },
  ): Promise<StrategyResult> {
    const code = c.req.query('code')
    if (!code) {
      const q = new URLSearchParams({
        code: 'test',
        state: JSON.stringify({ next: options.next ?? '', ...(options.state ?? {}) }),
      })
      return { type: 'redirect', url: `${this.callbackURL}?${q}` }
    }
    const state = JSON.parse(c.req.query('state') ?? '{}') as Record<string, string>
    return {
      type: 'success',
      user: { socialLogin: true },
      info: {
        profile: this.profile,
        tokens: {
          accessToken: 'test-access-token',
          refreshToken: 'test-refresh-token',
          expiresAt: Date.now() + 3600_000,
          raw: {},
        },
        next: state.next || undefined,
        state: { process: state.process },
      },
    }
  }
}

type Override = (key: string, callbackURL: string) => Strategy | undefined

interface ClientLike {
  get(path: string, opts?: any): Promise<Response>
  post(path: string, opts?: any): Promise<Response>
}

/**
 * Log in through `/accounts/<provider>/login/` as if the provider returned `profile`. Returns the callback response
 * (usually a redirect; the client is then logged in, or sent to `signup/`).
 *
 * ```ts
 * const res = await socialLogin(client, 'github', { id: '1', email: 'ann@example.com', emailVerified: true, username: 'ann' })
 * ```
 */
export async function socialLogin(
  client: ClientLike,
  key: string,
  profile: Partial<Profile> & { id: string },
  opts: { prefix?: string; next?: string; process?: 'login' | 'connect' } = {},
): Promise<Response> {
  const full: Profile = { provider: key, raw: { ...profile, id: profile.id }, ...profile } as Profile
  const g = globalThis as any
  const previous = g[TEST_STRATEGY_KEY] as Override | undefined
  g[TEST_STRATEGY_KEY] = ((k: string, callbackURL: string) =>
    k === key ? new FakeProviderStrategy(full, callbackURL) : previous?.(k, callbackURL)) as Override
  try {
    const prefix = (opts.prefix ?? '/accounts/').replace(/\/?$/, '/')
    const q = new URLSearchParams()
    if (opts.next) q.set('next', opts.next)
    if (opts.process) q.set('process', opts.process)
    const start = await client.post(`${prefix}${key}/login/${q.size ? `?${q}` : ''}`, { form: {} })
    const location = start.headers.get('location')
    // An error redirect from the start step (not to our callback): hand it back as is.
    if (start.status !== 302 || !location || !location.includes('/login/callback/')) return start
    return await client.get(location)
  } finally {
    g[TEST_STRATEGY_KEY] = previous
  }
}
