// Which providers are configured, and with which app credentials (settings first, then SocialApp rows).

import { SocialApp } from './models'
import { allProviders, getProvider, type Provider } from './providers'
import { type AppSettings, type ProviderSettings, socialSettings } from './settings'

export interface ResolvedProvider {
  /** The id in URLs and on `SocialAccount.provider`. */
  key: string
  provider: Provider
  app: AppSettings
  settings: ProviderSettings
  /** The `SocialApp` row, when the credentials came from the database. */
  row?: SocialApp
}

function fromRow(row: SocialApp): AppSettings {
  return {
    clientId: row.clientId,
    secret: row.secret || undefined,
    key: row.key || undefined,
    providerId: row.providerId || undefined,
    name: row.name,
    settings: (row.settings as Record<string, unknown>) ?? {},
  }
}

async function safeRows(filter: Record<string, unknown>): Promise<SocialApp[]> {
  try {
    return await SocialApp.objects.filter(filter).orderBy('id')
  } catch {
    return [] // table not migrated yet
  }
}

/** The provider for `key` (`github`, or the `providerId` of a multi-app provider), or null if not configured. */
export async function resolveProvider(key: string): Promise<ResolvedProvider | null> {
  const all = socialSettings().providers
  const direct = getProvider(key)
  if (direct && !direct.multipleApps) {
    const settings = all[key] ?? {}
    if (settings.APP) return { key, provider: direct, app: settings.APP, settings }
    const [row] = await safeRows({ provider: key })
    return row ? { key, provider: direct, app: fromRow(row), settings, row } : null
  }
  for (const provider of allProviders().filter((p) => p.multipleApps)) {
    const settings = all[provider.id] ?? {}
    const app = settings.APPS?.find((a) => a.providerId === key)
    if (app) return { key, provider, app, settings }
    const [row] = await safeRows({ provider: provider.id, providerId: key })
    if (row) return { key, provider, app: fromRow(row), settings, row }
  }
  return null
}

/** Every configured provider (for login buttons). */
export async function configuredProviders(): Promise<ResolvedProvider[]> {
  const all = socialSettings().providers
  const out: ResolvedProvider[] = []
  const seen = new Set<string>()
  for (const provider of allProviders()) {
    const settings = all[provider.id] ?? {}
    if (provider.multipleApps) {
      for (const app of settings.APPS ?? []) {
        if (app.providerId && !seen.has(app.providerId)) {
          seen.add(app.providerId)
          out.push({ key: app.providerId, provider, app, settings })
        }
      }
      for (const row of await safeRows({ provider: provider.id })) {
        if (row.providerId && !seen.has(row.providerId)) {
          seen.add(row.providerId)
          out.push({ key: row.providerId, provider, app: fromRow(row), settings, row })
        }
      }
    } else if (settings.APP) {
      seen.add(provider.id)
      out.push({ key: provider.id, provider, app: settings.APP, settings })
    }
  }
  for (const row of await safeRows({})) {
    const provider = getProvider(row.provider)
    if (provider && !provider.multipleApps && !seen.has(row.provider)) {
      seen.add(row.provider)
      out.push({ key: row.provider, provider, app: fromRow(row), settings: all[row.provider] ?? {}, row })
    }
  }
  return out
}
