// @ghuri/socialauth/admin — import from your project's admin module to manage social apps and accounts:
//   import '@ghuri/socialauth/admin'
import { ModelAdmin, site } from '@ghuri/admin'
import { SocialAccount, SocialApp, SocialToken } from './models'

export class SocialAppAdmin extends ModelAdmin<SocialApp> {
  override listDisplay = ['name', 'provider', 'providerId', 'clientId']
  override listFilter = ['provider']
  override searchFields = ['name', 'clientId', 'providerId']
}

export class SocialAccountAdmin extends ModelAdmin<SocialAccount> {
  override listDisplay = ['user', 'provider', 'uid', 'lastLogin', 'dateJoined']
  override listFilter = ['provider']
  override searchFields = ['uid', 'provider']
  override readonlyFields = ['extraData', 'lastLogin', 'dateJoined']
}

export class SocialTokenAdmin extends ModelAdmin<SocialToken> {
  override listDisplay = ['account', 'app', 'expiresAt']
  // Tokens are encrypted; never show or edit them in the admin.
  override exclude = ['token', 'tokenSecret']
  override readonlyFields = ['account', 'app', 'expiresAt']
}

site.register(SocialApp, SocialAppAdmin)
site.register(SocialAccount, SocialAccountAdmin)
site.register(SocialToken, SocialTokenAdmin)
