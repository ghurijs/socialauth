// Provider tokens (STORE_TOKENS), encrypted at rest with a key derived from SECRET_KEY.
import { OAuth2Strategy, type OAuthTokens, seal, unseal } from '@ghuri/oauth'
import type { SocialLogin } from './login'
import { type SocialAccount, SocialToken } from './models'
import { resolveProvider } from './resolve'
import { socialSettings } from './settings'

const PURPOSE = 'socialauth-token'

export async function storeTokens(login: SocialLogin, account: SocialAccount): Promise<void> {
  if (!socialSettings().storeTokens || !login.tokens?.accessToken) return
  const t = login.tokens
  const app = login.row ?? null
  const existing = await SocialToken.objects.filter({ account, app } as any).first()
  const values = {
    token: await seal(t.accessToken, PURPOSE),
    tokenSecret: t.refreshToken ? await seal(t.refreshToken, PURPOSE) : (existing?.tokenSecret ?? ''),
    expiresAt: t.expiresAt ? new Date(t.expiresAt) : null,
  }
  if (existing) {
    Object.assign(existing, values)
    await existing.save()
  } else {
    await SocialToken.objects.create({ account, app, ...values } as any)
  }
}

/**
 * A usable access token for the account (refreshed with the stored refresh token when it expired), or null
 * when tokens are not stored or cannot be refreshed.
 */
export async function getAccessToken(account: SocialAccount): Promise<string | null> {
  const row = await SocialToken.objects.filter({ account } as any).first()
  if (!row) return null
  const access = await unseal(row.token, PURPOSE)
  const expiresAt = row.expiresAt ? new Date(row.expiresAt as any).getTime() : undefined
  if (access && (!expiresAt || expiresAt - 30_000 > Date.now())) return access
  const refresh = row.tokenSecret ? await unseal(row.tokenSecret, PURPOSE) : null
  if (!refresh) return null
  const resolved = await resolveProvider(account.provider)
  if (!resolved) return null
  const strategy = resolved.provider.createStrategy({
    key: resolved.key,
    app: resolved.app,
    settings: resolved.settings,
    callbackURL: '/',
    verify: async () => null,
  })
  if (!(strategy instanceof OAuth2Strategy)) return null
  let tokens: OAuthTokens
  try {
    tokens = await (await strategy.client()).refresh(refresh)
  } catch {
    return null
  }
  row.token = await seal(tokens.accessToken, PURPOSE)
  if (tokens.refreshToken) row.tokenSecret = await seal(tokens.refreshToken, PURPOSE)
  row.expiresAt = (tokens.expiresAt ? new Date(tokens.expiresAt) : null) as any
  await row.save()
  return tokens.accessToken
}
