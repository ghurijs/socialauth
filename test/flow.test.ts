// The social login flow (signup, linking, connect, disconnect, SPA codes, tokens) through the real views.
import { User } from '@ghuri/auth'
import { createTestClient, type TestClient } from '@ghuri/core/testing'
import { makeMigrations } from '@ghuri/orm/migrations'
import { beforeEach, describe, expect, it } from 'vitest'
import { getAccessToken, SocialAccount, SocialAccountAdapter, SocialApp, SocialToken } from '../src/index'
import { socialLogin } from '../src/testing'
import { JSON_HEADERS, useSocialApp } from './helpers'

const ann = { id: '101', username: 'ann', email: 'ann@example.com', emailVerified: true, name: 'Ann Lee' }

class ClosedAdapter extends SocialAccountAdapter {
  override isOpenForSignup() {
    return false
  }
}

describe('social login flow', () => {
  const h = useSocialApp(() => ({
    PROVIDERS: {
      github: { APP: { clientId: 'gh-id', secret: 'gh-secret' } },
      google: { APP: { clientId: 'g-id', secret: 'g-secret' } },
      openid_connect: {
        APPS: [
          {
            providerId: 'okta',
            name: 'Okta',
            clientId: 'o-id',
            settings: { serverUrl: 'https://okta.test' },
          },
        ],
      },
    },
  }))
  let client: TestClient
  beforeEach(() => {
    client = createTestClient(h.app, { env: h.env })
  })
  const me = async (c = client) =>
    (await (await c.get('/accounts/me/', { headers: JSON_HEADERS })).json()) as any

  it('ships a migration that matches the models', async () => {
    const result = await makeMigrations({ appLabels: ['socialaccount'], check: true, interactive: false })
    expect(result.exitCode).toBe(0)
  })

  it('lists configured providers from settings and SocialApp rows', async () => {
    await SocialApp.objects.create({ provider: 'discord', name: 'Discord', clientId: 'd-id', secret: 's' })
    const res = await client.get('/accounts/providers/', { headers: JSON_HEADERS })
    const { providers } = (await res.json()) as any
    expect(providers.map((p: any) => p.id).sort()).toEqual(['discord', 'github', 'google', 'okta'])
    expect(providers.find((p: any) => p.id === 'okta')).toMatchObject({
      name: 'Okta',
      loginUrl: '/accounts/okta/login/',
    })
    expect((await client.get('/accounts/nope/login/', { headers: JSON_HEADERS })).status).toBe(302)
  })

  it('asks for confirmation on GET and starts on POST', async () => {
    const page = await client.get('/accounts/github/login/?next=/x/')
    expect(page.status).toBe(200)
    expect(await page.text()).toContain('<form method="post" action="/accounts/github/login/?next=/x/">')
    expect((await client.get('/accounts/github/login/', { headers: JSON_HEADERS })).status).toBe(405)
    const start = await client.post('/accounts/github/login/', { form: {} })
    expect(start.status).toBe(302)
    expect(start.headers.get('location')).toMatch(/^https:\/\/github\.com\/login\/oauth\/authorize\?/)
    expect(new URL(start.headers.get('location')!).searchParams.get('redirect_uri')).toBe(
      'http://testserver/accounts/github/login/callback/',
    )
  })

  it('signs up a new user, then logs the same user in again', async () => {
    const res = await socialLogin(client, 'github', ann, { next: '/dashboard/' })
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe('/dashboard/')
    expect((await me()).user).toMatchObject({ username: 'ann' })
    const user = (await User.objects.get({ username: 'ann' })) as any
    expect(user.email).toBe('ann@example.com')
    expect(user.hasUsablePassword()).toBe(false)
    expect(user.firstName).toBe('Ann')
    expect(user.lastName).toBe('Lee')

    const other = createTestClient(h.app, { env: h.env })
    await socialLogin(other, 'github', { ...ann, name: 'Ann B. Lee' })
    expect((await me(other)).user.username).toBe('ann')
    expect(await SocialAccount.objects.count()).toBe(1)
    expect((await SocialAccount.objects.first())!.extraData).toMatchObject({ name: 'Ann B. Lee' })
  })

  it('picks a free username and ignores unsafe next URLs', async () => {
    await User.objects.createUser('ann', 'other@example.com', 'pw')
    const res = await socialLogin(client, 'github', ann, { next: 'https://evil.example/' })
    expect(res.headers.get('location')).toBe('/home/')
    expect((await me()).user.username).toBe('ann2')
  })

  it('sends people whose email is taken to the signup form instead of linking', async () => {
    await User.objects.createUser('existing', 'ann@example.com', 'pw')
    const res = await socialLogin(client, 'github', ann)
    expect(res.headers.get('location')).toBe('/accounts/signup/')
    expect((await me()).isAuthenticated).toBe(false)

    const form = await client.get('/accounts/signup/', { headers: JSON_HEADERS })
    expect(await form.json()).toMatchObject({
      provider: 'github',
      fields: ['username', 'email'],
      profile: { email: 'ann@example.com' },
    })
    const html = await client.get('/accounts/signup/')
    expect(await html.text()).toContain('value="ann@example.com"')

    const again = await client.post('/accounts/signup/', {
      json: { username: 'ann', email: 'ann@example.com' },
      headers: JSON_HEADERS,
    })
    expect(again.status).toBe(400)
    expect(((await again.json()) as any).errors.email[0]).toMatch(/already uses this address/)
    const done = await client.post('/accounts/signup/', {
      json: { username: 'ann', email: 'ann.lee@example.com' },
      headers: JSON_HEADERS,
    })
    expect(done.status).toBe(200)
    expect((await me()).user).toMatchObject({ username: 'ann' })
    expect(((await User.objects.get({ username: 'ann' })) as any).email).toBe('ann.lee@example.com')
    expect((await client.get('/accounts/signup/', { headers: JSON_HEADERS })).status).toBe(400)
  })

  it('links by verified email only with EMAIL_AUTHENTICATION', async () => {
    h.social.EMAIL_AUTHENTICATION = true
    const existing = await User.objects.createUser('existing', 'ann@example.com', 'pw')
    const unverified = await socialLogin(client, 'github', { ...ann, emailVerified: false })
    expect(unverified.headers.get('location')).toBe('/accounts/signup/')
    const verified = await socialLogin(createTestClient(h.app, { env: h.env }), 'github', ann)
    expect(verified.headers.get('location')).toBe('/home/')
    const account = (await SocialAccount.objects.first())!
    expect((account as any).userId).toBe(existing.pk)
  })

  it('connects and disconnects accounts for a logged-in user', async () => {
    const user = await User.objects.createUser('bob', 'bob@example.com', 'pw')
    await client.forceLogin(user)
    const res = await socialLogin(client, 'github', ann, { process: 'connect' })
    expect(res.headers.get('location')).toBe('/accounts/connections/')
    const list = (await (await client.get('/accounts/connections/', { headers: JSON_HEADERS })).json()) as any
    expect(list.accounts).toHaveLength(1)

    const intruder = createTestClient(h.app, { env: h.env })
    await intruder.forceLogin(await User.objects.createUser('eve', 'eve@example.com', 'pw'))
    const stolen = await socialLogin(intruder, 'github', ann, { process: 'connect' })
    expect(new URL(stolen.headers.get('location')!, 'http://x').searchParams.get('error')).toMatch(
      /already connected/,
    )

    const off = await client.post('/accounts/connections/', {
      json: { account: list.accounts[0].id },
      headers: JSON_HEADERS,
    })
    expect(await off.json()).toEqual({ disconnected: String(list.accounts[0].id) })
    expect(await SocialAccount.objects.count()).toBe(0)
    expect(
      (
        await socialLogin(createTestClient(h.app, { env: h.env }), 'github', ann, { process: 'connect' })
      ).headers.get('location'),
    ).toMatch(/error=/)
  })

  it('refuses to disconnect the last login method of a user without a password', async () => {
    await socialLogin(client, 'github', ann)
    const [account] = (
      (await (await client.get('/accounts/connections/', { headers: JSON_HEADERS })).json()) as any
    ).accounts
    const res = await client.post('/accounts/connections/', {
      json: { account: account.id },
      headers: JSON_HEADERS,
    })
    expect(res.status).toBe(400)
    expect(((await res.json()) as any).code).toBe('last_login_method')
    expect((await client.get('/accounts/connections/', { headers: JSON_HEADERS })).status).toBe(200)
    expect(
      (await createTestClient(h.app, { env: h.env }).get('/accounts/connections/', { headers: JSON_HEADERS }))
        .status,
    ).toBe(401)
  })

  it('hands SPAs a one-time code, exchanged for a JWT pair once', async () => {
    h.social.LOGIN_RESPONSE = 'jwt'
    h.social.FRONTEND_URL = 'https://app.example.com/auth/callback'
    const res = await socialLogin(client, 'github', ann)
    const location = res.headers.get('location')!
    expect(location.startsWith('https://app.example.com/auth/callback#code=')).toBe(true)
    expect((await me()).isAuthenticated).toBe(false)
    const code = decodeURIComponent(location.split('#code=')[1])
    const form = await client.post('/accounts/token/', { form: { code } })
    expect(form.status).toBe(415)
    const pair = await client.post('/accounts/token/', { json: { code } })
    expect(pair.status).toBe(200)
    expect(await pair.json()).toMatchObject({
      user: { username: 'ann' },
      access: expect.any(String),
      refresh: expect.any(String),
    })
    expect((await client.post('/accounts/token/', { json: { code } })).status).toBe(400)
  })

  it('stores provider tokens encrypted when STORE_TOKENS is on', async () => {
    h.social.STORE_TOKENS = true
    await socialLogin(client, 'github', ann)
    const row = (await SocialToken.objects.first())!
    expect(row.token).not.toContain('test-access-token')
    expect(await getAccessToken((await SocialAccount.objects.first())!)).toBe('test-access-token')
  })

  it('honors the adapter and inactive users', async () => {
    h.social.ADAPTER = ClosedAdapter
    const closed = await socialLogin(client, 'github', ann)
    expect(new URL(closed.headers.get('location')!, 'http://x').searchParams.get('error')).toBe(
      'Sign-ups are closed.',
    )
    delete h.social.ADAPTER
    await socialLogin(client, 'github', ann)
    await User.objects.filter({ username: 'ann' }).update({ isActive: false })
    const inactive = await socialLogin(createTestClient(h.app, { env: h.env }), 'github', ann)
    expect(new URL(inactive.headers.get('location')!, 'http://x').searchParams.get('error')).toBe(
      'This account is inactive.',
    )
  })
})
