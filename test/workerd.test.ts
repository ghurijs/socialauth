// The socialauth bundle on workerd: providers list and the start of the GitHub login (state cookie, PKCE).
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { Miniflare } from 'miniflare'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

describe('socialauth on workerd', () => {
  let mf: Miniflare
  beforeAll(async () => {
    const out = await build({
      entryPoints: [fileURLToPath(new URL('./fixtures/worker.ts', import.meta.url))],
      bundle: true,
      format: 'esm',
      platform: 'neutral',
      target: 'es2022',
      mainFields: ['module', 'main'],
      conditions: ['workerd', 'worker', 'browser', 'import'],
      external: ['node:*', 'cloudflare:*', 'postgres'],
      write: false,
      logLevel: 'silent',
    })
    mf = new Miniflare({
      modules: true,
      script: out.outputFiles[0].text,
      compatibilityDate: '2025-06-01',
      compatibilityFlags: ['nodejs_compat'],
      d1Databases: { DB: `social-${crypto.randomUUID()}` },
      bindings: { GH_ID: 'edge-gh' },
    })
  }, 60_000)
  afterAll(async () => {
    await mf?.dispose()
  })

  it('lists providers and starts a GitHub login', async () => {
    const list = await mf.dispatchFetch('https://example.com/accounts/providers/')
    expect(await list.json()).toMatchObject({
      providers: [{ id: 'github', loginUrl: '/accounts/github/login/' }],
    })
    const start = await mf.dispatchFetch('https://example.com/accounts/github/login/?next=/x/', {
      redirect: 'manual',
    })
    expect(start.status).toBe(302)
    const auth = new URL(start.headers.get('location')!)
    expect(auth.origin + auth.pathname).toBe('https://github.com/login/oauth/authorize')
    expect(auth.searchParams.get('client_id')).toBe('edge-gh')
    expect(auth.searchParams.get('redirect_uri')).toBe('https://example.com/accounts/github/login/callback/')
    expect(auth.searchParams.get('code_challenge_method')).toBe('S256')
    expect(start.headers.get('set-cookie')).toMatch(
      /^ghuri_oauth=.+; Max-Age=600; Path=\/; HttpOnly; Secure; SameSite=Lax/,
    )
  })
})
