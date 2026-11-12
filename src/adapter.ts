// The adapter (django-allauth's DefaultSocialAccountAdapter): override to customize signup and linking.
import { getUserModel } from '@ghuri/auth'
import { reverse } from '@ghuri/core'
import type { Context } from 'hono'
import type { SocialLogin } from './login'
import type { SocialAccount } from './models'
import { socialSettings } from './settings'

/** Throw from `preSocialLogin()` to answer with your own response. */
export class ImmediateResponse extends Error {
  constructor(readonly response: Response) {
    super('ImmediateResponse')
  }
}

export interface SignupData {
  username?: string
  email?: string
}

const USERNAME_ALLOWED = /[^\w.@+-]/g

export class SocialAccountAdapter {
  /** May new users sign up through social login? */
  isOpenForSignup(_c: Context, _login: SocialLogin): boolean | Promise<boolean> {
    return true
  }

  /** Called after the provider answered, before anything is looked up or created. */
  async preSocialLogin(_c: Context, _login: SocialLogin): Promise<void> {}

  /** May the user be created without showing the signup form? */
  isAutoSignupAllowed(_c: Context, login: SocialLogin): boolean | Promise<boolean> {
    const s = socialSettings()
    if (!s.autoSignup) return false
    if (s.emailRequired && !login.profile.email) return false
    return true
  }

  /** A new, unsaved user instance. */
  newUser(_c: Context, _login: SocialLogin): any {
    const User = getUserModel()
    return new (User as any)()
  }

  /** Copy profile data (and signup form data) onto the new user. */
  populateUser(_c: Context, login: SocialLogin, user: any, data: SignupData): any {
    const M = user.constructor as { USERNAME_FIELD: string; EMAIL_FIELD: string; _meta: any }
    const has = (f: string) => !!M._meta.getField?.(f)
    if (data.username !== undefined) user[M.USERNAME_FIELD] = data.username
    if (data.email !== undefined && has(M.EMAIL_FIELD)) user[M.EMAIL_FIELD] = data.email
    if (has('firstName') && login.profile.firstName) user.firstName = login.profile.firstName.slice(0, 150)
    if (has('lastName') && login.profile.lastName) user.lastName = login.profile.lastName.slice(0, 150)
    if (has('firstName') && !login.profile.firstName && login.profile.name && has('lastName')) {
      const [first, ...rest] = login.profile.name.trim().split(/\s+/)
      user.firstName = (first ?? '').slice(0, 150)
      user.lastName = rest.join(' ').slice(0, 150)
    }
    return user
  }

  /** Save the new user (with an unusable password). */
  async saveUser(_c: Context, _login: SocialLogin, user: any): Promise<any> {
    if (typeof user.setUnusablePassword === 'function') user.setUnusablePassword()
    await user.save()
    return user
  }

  /** Username candidates, best first. */
  usernameCandidates(login: SocialLogin): string[] {
    const p = login.profile
    return [p.username, p.email?.split('@')[0], p.name, p.firstName, `${login.key}${p.id}`].filter(
      (v): v is string => typeof v === 'string' && v.trim().length > 0,
    )
  }

  /** A username that is free, from the profile. */
  async generateUsername(_c: Context, login: SocialLogin): Promise<string> {
    const User = getUserModel()
    const field = User.USERNAME_FIELD
    const maxLength = (User._meta.getField(field) as { maxLength?: number } | undefined)?.maxLength ?? 150
    const taken = async (name: string) => User.objects.filter({ [`${field}__iexact`]: name } as any).exists()
    for (const raw of this.usernameCandidates(login)) {
      const base = raw.trim().replace(/\s+/g, '').replace(USERNAME_ALLOWED, '').slice(0, maxLength)
      if (!base) continue
      if (!(await taken(base))) return base
      for (let i = 2; i < 100; i++) {
        const suffix = String(i)
        const candidate = `${base.slice(0, maxLength - suffix.length)}${suffix}`
        if (!(await taken(candidate))) return candidate
      }
    }
    return `user${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`
  }

  /** Where to go after connecting an account. */
  getConnectRedirectUrl(_c: Context, _account: SocialAccount): string {
    try {
      return reverse('socialaccount_connections')
    } catch {
      return '/'
    }
  }

  /** Customize error responses; return undefined for the default. */
  authenticationError(
    _c: Context,
    _error: { provider: string; message: string; code?: string },
  ): Response | undefined | Promise<Response | undefined> {
    return undefined
  }
}

const cache = new WeakMap<object, SocialAccountAdapter>()
let fallback: SocialAccountAdapter | undefined

export function getAdapter(): SocialAccountAdapter {
  const cls = socialSettings().adapter
  if (!cls) {
    fallback ??= new SocialAccountAdapter()
    return fallback
  }
  let a = cache.get(cls)
  if (!a) {
    a = new cls()
    cache.set(cls, a)
  }
  return a
}
