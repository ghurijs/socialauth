// Real provider strategies against the mock provider (provider URLs intercepted): GitHub's REST profile and
// emails, Google's OIDC (discovery, JWKS, ID token), Microsoft's email rule, native-token login.
import { User } from '@ghuri/auth'
import { createTestClient } from '@ghuri/core/testing'
import { providerFetch } from '@ghuri/oauth'
import { followOAuth, type MockProvider, mockOAuthProvider } from '@ghuri/oauth/testing'
import { afterEach, describe, expect, it } from 'vitest'
import { getProvider, SocialAccount } from '../src/index'
import { JSON_HEADERS, useSocialApp } from './helpers'

/** Run a code flow by hand against the mock to get an ID token issued to `clientId`. */
async function idTokenFor(provider: MockProvider, clientId: string): Promise<string> {
  const callback = new URL(
    provider.authorize(
      `${provider.issuer}/authorize?client_id=${clientId}&redirect_uri=http://app.test/cb&scope=openid%20email&state=s`,
    ),
  )
  const res = await providerFetch(provider.endpoints.token, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: callback.searchParams.get('code')!,
      redirect_uri: 'http://app.test/cb',
    }),
  })
  return ((await res.json()) as any).id_token
}

describe('provider strategies', () => {
  const h = useSocialApp(() => ({
    PROVIDERS: {
      github: { APP: { clientId: 'gh-id', secret: 'gh-secret' } },
      google: { APP: { clientId: 'g-id', secret: 'g-secret', settings: { audiences: ['g-ios'] } } },
      microsoft: {
        APP: {
          clientId: 'ms-id',
          secret: 'ms-secret',
          settings: { tenant: '11111111-2222-3333-4444-555555555555' },
        },
      },
      facebook: { APP: { clientId: 'fb-app', secret: 'fb-secret' } },
    },
  }))
  let provider: MockProvider | undefined
  afterEach(() => provider?.restore())
  const userOf = async (account: SocialAccount) => User.objects.get({ pk: (account as any).userId })

  it('GitHub: code flow, /user and the verified primary email from /user/emails', async () => {
    provider = mockOAuthProvider({
      issuer: 'https://github.com',
      routes: {
        'https://api.github.com/user': {
          id: 9001,
          login: 'octo',
          name: 'Octo Cat',
          email: null,
          avatar_url: 'https://a/x.png',
        },
        'https://api.github.com/user/emails': [
          { email: 'old@example.com', primary: false, verified: true },
          { email: 'octo@example.com', primary: true, verified: true },
        ],
      },
    })
    const client = createTestClient(h.app, { env: h.env })
    const res = await followOAuth(client, '/accounts/github/login/', provider, { method: 'POST' })
    expect(res.headers.get('location')).toBe('/home/')
    const account = (await SocialAccount.objects.get({ provider: 'github' }))!
    expect(account.uid).toBe('9001')
    const user = (await userOf(account)) as any
    expect([user.username, user.email]).toEqual(['octo', 'octo@example.com'])
    const token = provider.requests.find((r) => r.url === 'https://github.com/login/oauth/access_token')
    expect(token?.method).toBe('POST')
  })

  it('Google: OIDC discovery, signed ID token, email_verified', async () => {
    provider = mockOAuthProvider({
      issuer: 'https://accounts.google.com',
      profile: {
        sub: 'g-123',
        email: 'gina@example.com',
        email_verified: true,
        given_name: 'Gina',
        family_name: 'Ray',
      },
    })
    const client = createTestClient(h.app, { env: h.env })
    const start = await client.post('/accounts/google/login/', { form: {} })
    const auth = new URL(start.headers.get('location')!)
    expect(auth.origin).toBe('https://accounts.google.com')
    expect(auth.searchParams.get('scope')).toBe('openid email profile')
    const cb = new URL(provider.authorize(auth.toString()))
    expect((await client.get(cb.pathname + cb.search)).headers.get('location')).toBe('/home/')
    const user = (await userOf((await SocialAccount.objects.get({ provider: 'google' }))!)) as any
    expect([user.username, user.firstName, user.lastName]).toEqual(['gina', 'Gina', 'Ray'])
  })

  it('Microsoft emails never count as verified', async () => {
    const ms = getProvider('microsoft')!
    const profile = ms.profileFromClaims('microsoft', {
      sub: 's',
      oid: 'o-1',
      email: 'x@corp.example',
      email_verified: true,
    })
    expect(profile.id).toBe('o-1')
    expect(ms.emailVerified(profile, {})).toBe(false)
    expect(ms.emailVerified(profile, { VERIFIED_EMAIL: true })).toBe(true)
    expect(
      getProvider('facebook')!.emailVerified(
        { provider: 'facebook', id: '1', email: 'f@x.dev', emailVerified: false, raw: {} },
        {},
      ),
    ).toBe(false)
  })

  it('native login with a Google ID token checks the audience', async () => {
    provider = mockOAuthProvider({
      issuer: 'https://accounts.google.com',
      profile: { sub: 'g-9', email: 'nat@example.com', email_verified: true },
    })
    const client = createTestClient(h.app, { env: h.env })
    const ok = await client.post('/accounts/google/token/', {
      json: { id_token: await idTokenFor(provider, 'g-ios') },
      headers: JSON_HEADERS,
    })
    expect(ok.status).toBe(200)
    expect(await ok.json()).toMatchObject({ user: { username: 'nat' } })
    expect(
      ((await (await client.get('/accounts/me/', { headers: JSON_HEADERS })).json()) as any).isAuthenticated,
    ).toBe(true)

    const wrong = await client.post('/accounts/google/token/', {
      json: { id_token: await idTokenFor(provider, 'someone-else') },
      headers: JSON_HEADERS,
    })
    expect(wrong.status).toBe(401)
    const form = await client.post('/accounts/google/token/', { form: { id_token: 'x' } })
    expect(form.status).toBe(415)
    const discord = await client.post('/accounts/github/token/', {
      json: { id_token: 'x' },
      headers: JSON_HEADERS,
    })
    expect(discord.status).toBe(401)
  })

  it('native login with a Facebook access token checks debug_token', async () => {
    const debug = { data: { is_valid: true, app_id: 'fb-app' } }
    provider = mockOAuthProvider({ issuer: 'https://www.facebook.com', profile: {} })
    const graph = 'https://graph.facebook.com/v21.0'
    const original = (provider as any).handle.bind(provider)
    ;(provider as any).handle = async (req: Request) => {
      const url = req.url.split('?')[0]
      if (url === `${graph}/debug_token`) return Response.json(debug)
      if (url === `${graph}/me`)
        return Response.json({ id: 'fb-1', name: 'Fay Book', email: 'fay@example.com' })
      return original(req)
    }
    const { setProviderFetch } = await import('@ghuri/oauth')
    setProviderFetch((input, init) => (provider as any).handle(new Request(input as any, init)))
    const client = createTestClient(h.app, { env: h.env })
    const ok = await client.post('/accounts/facebook/token/', {
      json: { access_token: 'fb-token' },
      headers: JSON_HEADERS,
    })
    expect(ok.status).toBe(200)
    debug.data.app_id = 'another-app'
    const stolen = await createTestClient(h.app, { env: h.env }).post('/accounts/facebook/token/', {
      json: { access_token: 'fb-token' },
      headers: JSON_HEADERS,
    })
    expect(stolen.status).toBe(401)
  })
})
