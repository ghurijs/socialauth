// django-allauth's socialaccount models (same table names): apps, linked accounts, provider tokens.
import { getUserModel } from '@ghuri/auth'
import {
  CASCADE,
  CharField,
  DateTimeField,
  ForeignKey,
  JSONField,
  type Manager,
  Model,
  type ModelClass,
  TextField,
} from '@ghuri/orm'

const userModel = () => getUserModel() as unknown as ModelClass

/** Default of the JSON fields (a named function, so migrations can reference it). */
export function emptyDict(): Record<string, unknown> {
  return {}
}

/** Provider credentials kept in the database (alternative to `SOCIALACCOUNT.PROVIDERS.<id>.APP`). */
export class SocialApp extends Model({
  provider: new CharField({ maxLength: 30, verboseName: 'provider' }),
  /** For providers with several apps (`openid_connect`): the id used in URLs. */
  providerId: new CharField({ maxLength: 200, blank: true, verboseName: 'provider ID' }),
  name: new CharField({ maxLength: 40, verboseName: 'name' }),
  clientId: new CharField({ maxLength: 191, verboseName: 'client id' }),
  secret: new CharField({ maxLength: 191, blank: true, verboseName: 'secret key' }),
  key: new CharField({ maxLength: 191, blank: true, verboseName: 'key' }),
  settings: new JSONField({ default: emptyDict, blank: true, verboseName: 'settings' }),
}) {
  static Meta = {
    dbTable: 'socialaccount_socialapp',
    verboseName: 'social application',
    verboseNamePlural: 'social applications',
  }
  declare static objects: Manager<SocialApp>

  override toString(): string {
    return this.name
  }
}

/** A provider account linked to a user. */
export class SocialAccount extends Model({
  user: new ForeignKey(userModel, { onDelete: CASCADE, relatedName: 'socialAccounts', verboseName: 'user' }),
  /** The provider id (`github`, or the `providerId` of an OpenID Connect app). */
  provider: new CharField({ maxLength: 200, verboseName: 'provider' }),
  uid: new CharField({ maxLength: 191, verboseName: 'uid' }),
  lastLogin: new DateTimeField({ autoNow: true, verboseName: 'last login' }),
  dateJoined: new DateTimeField({ autoNowAdd: true, verboseName: 'date joined' }),
  /** The provider's raw profile. */
  extraData: new JSONField({ default: emptyDict, verboseName: 'extra data' }),
}) {
  static Meta = {
    dbTable: 'socialaccount_socialaccount',
    uniqueTogether: [['provider', 'uid']],
    verboseName: 'social account',
    verboseNamePlural: 'social accounts',
  }
  declare static objects: Manager<SocialAccount>

  override toString(): string {
    return `${this.provider}:${this.uid}`
  }
}

/** Provider tokens (only with `STORE_TOKENS`), encrypted at rest. Read them with `getAccessToken()`. */
export class SocialToken extends Model({
  app: new ForeignKey(() => SocialApp, { onDelete: CASCADE, null: true, blank: true }),
  account: new ForeignKey(() => SocialAccount, { onDelete: CASCADE, relatedName: 'tokens' }),
  token: new TextField({ verboseName: 'token' }),
  /** The refresh token (allauth's name). */
  tokenSecret: new TextField({ blank: true, verboseName: 'token secret' }),
  expiresAt: new DateTimeField({ null: true, blank: true, verboseName: 'expires at' }),
}) {
  static Meta = {
    dbTable: 'socialaccount_socialtoken',
    uniqueTogether: [['app', 'account']],
    verboseName: 'social application token',
    verboseNamePlural: 'social application tokens',
  }
  declare static objects: Manager<SocialToken>
}
