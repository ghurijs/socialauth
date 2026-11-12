// A Worker with social login (providers from settings; D1 configured but not needed for these routes).
import {
  AuthConfig,
  AuthenticationMiddleware,
  ContentTypesConfig,
  SessionMiddleware,
  SessionsConfig,
} from '@ghuri/auth'
import { createApp, defineSettings, include, path } from '@ghuri/core'
import { d1 } from '@ghuri/orm'
import { SocialAuthConfig, socialUrls } from '../../src/index'

export default createApp(
  defineSettings((env) => ({
    SECRET_KEY: 'edge-secret',
    INSTALLED_APPS: [ContentTypesConfig, AuthConfig, SessionsConfig, SocialAuthConfig],
    MIDDLEWARE: [SessionMiddleware, AuthenticationMiddleware],
    SESSION_ENGINE: 'signedCookie',
    ROOT_URLCONF: [path('accounts/', include(socialUrls))],
    DATABASES: { default: d1('DB') },
    SOCIALACCOUNT: {
      LOGIN_ON_GET: true,
      PROVIDERS: { github: { APP: { clientId: env.GH_ID, secret: 'x' } } },
    },
  })),
  { checks: false },
)
