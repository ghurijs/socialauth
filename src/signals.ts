import { Signal } from '@ghuri/core'
import type { Context } from 'hono'
import type { SocialLogin } from './login'
import type { SocialAccount } from './models'

const g = globalThis as any
function singleton<T>(key: string, make: () => T): T {
  const k = Symbol.for(key)
  if (!g[k]) g[k] = make()
  return g[k]
}

/** Before a social login is processed (after the provider answered). */
export const preSocialLogin: Signal<{ c: Context; login: SocialLogin }> = singleton(
  'ghuri.socialauth.preSocialLogin',
  () => new Signal('preSocialLogin'),
)
/** A provider account was linked to a user (signup or connect). */
export const socialAccountAdded: Signal<{ c: Context; login: SocialLogin; account: SocialAccount }> =
  singleton('ghuri.socialauth.socialAccountAdded', () => new Signal('socialAccountAdded'))
/** An existing link logged in again (profile and tokens refreshed). */
export const socialAccountUpdated: Signal<{ c: Context; login: SocialLogin; account: SocialAccount }> =
  singleton('ghuri.socialauth.socialAccountUpdated', () => new Signal('socialAccountUpdated'))
/** A link was removed from the connections page. */
export const socialAccountRemoved: Signal<{ c: Context; account: SocialAccount }> = singleton(
  'ghuri.socialauth.socialAccountRemoved',
  () => new Signal('socialAccountRemoved'),
)
