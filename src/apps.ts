import * as auth from '@ghuri/auth'
import { AppConfig, apps, ImproperlyConfigured } from '@ghuri/core'
import * as migrations from './migrations/index'
import { SocialAccount, SocialApp, SocialToken } from './models'

function appPath(): string | undefined {
  const meta = import.meta as ImportMeta & { dirname?: string; filename?: string }
  const dir = meta.dirname
  if (!dir || !/[\\/]src$/.test(dir) || !/\.[cm]?ts$/.test(meta.filename ?? '')) return undefined
  return dir
}

function migrationsModule(): Record<string, unknown> {
  const adapt = (auth as Record<string, any>).migrationsForUserModel
  return typeof adapt === 'function' ? adapt('socialaccount', migrations) : migrations
}

/** The `socialaccount` app (django-allauth's): `SocialApp`, `SocialAccount`, `SocialToken`. */
export class SocialAuthConfig extends AppConfig {
  name = '@ghuri/socialauth'
  override label = 'socialaccount'
  override verboseName = 'Social Accounts'
  override path = appPath()
  override migrations = migrationsModule()
  override models = { SocialApp, SocialAccount, SocialToken }

  override ready(): void {
    if (!apps.isInstalled('auth')) {
      throw new ImproperlyConfigured(
        "'socialaccount' requires '@ghuri/auth': add AuthConfig (and ContentTypesConfig) to INSTALLED_APPS.",
      )
    }
  }
}
