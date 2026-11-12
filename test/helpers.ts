import {
  AuthConfig,
  AuthenticationMiddleware,
  authUrls,
  ContentType,
  ContentTypesConfig,
  PBKDF2PasswordHasher,
  SessionMiddleware,
  SessionsConfig,
} from '@ghuri/auth'
import { CsrfMiddleware, createApp, defineSettings, type GhuriApp, include, path } from '@ghuri/core'
import { setupTestDatabase, type TestDatabase } from '@ghuri/orm/testing'
import { afterAll, beforeAll, beforeEach } from 'vitest'
import { SocialAuthConfig, socialUrls } from '../src/index'

export interface Harness {
  app: GhuriApp
  db: TestDatabase
  env: Record<string, unknown>
  /** Mutable SOCIALACCOUNT settings (reset before each test to `base`). */
  social: Record<string, any>
}

export function useSocialApp(base: () => Record<string, any>): Harness {
  const h = { env: {}, social: {} } as Harness
  beforeAll(async () => {
    h.app = createApp(
      defineSettings(() => ({
        SECRET_KEY: 'socialauth-tests',
        ALLOWED_HOSTS: ['testserver'],
        INSTALLED_APPS: [ContentTypesConfig, AuthConfig, SessionsConfig, SocialAuthConfig],
        MIDDLEWARE: [SessionMiddleware, CsrfMiddleware, AuthenticationMiddleware],
        ROOT_URLCONF: [path('accounts/', include(authUrls)), path('accounts/', include(socialUrls))],
        PASSWORD_HASHERS: [new PBKDF2PasswordHasher({ iterations: 1000 })],
        LOGIN_REDIRECT_URL: '/home/',
        SOCIALACCOUNT: h.social,
      })),
      { checks: false },
    )
    await h.app.setup(h.env)
    h.db = await setupTestDatabase({ using: 'sqlite' })
  }, 60_000)
  afterAll(async () => {
    await h.db?.teardown()
  })
  beforeEach(async () => {
    ContentType.objects.clearCache()
    await h.db.flush()
    ContentType.objects.clearCache()
    for (const k of Object.keys(h.social)) delete h.social[k]
    Object.assign(h.social, base())
  })
  return h
}

export const JSON_HEADERS = { accept: 'application/json' }
