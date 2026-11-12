# @ghuri/socialauth

"Log in with GitHub / Google / Facebook…" for [Ghuri](https://github.com/ghurijs/ghuri), like **django-allauth**'s
`socialaccount`: configure providers in settings and include the URLs. Accounts are linked to users with the same
tables as allauth, new users sign up automatically, existing users connect more providers, and SPAs and mobile apps get
JSON endpoints. Built on [`@ghuri/oauth`](https://github.com/ghurijs/oauth); runs on Cloudflare Workers and Node.

> Status: alpha (ARCHITECTURE.md §18). Needs `@ghuri/auth` 0.1.0-alpha.2 and `@ghuri/oauth`.

```sh
npm install @ghuri/socialauth @ghuri/oauth
```

## Setup

```ts
// src/settings.ts
import { AuthConfig, ContentTypesConfig, SessionsConfig } from '@ghuri/auth'
import { SocialAuthConfig } from '@ghuri/socialauth'

INSTALLED_APPS: [ContentTypesConfig, AuthConfig, SessionsConfig, SocialAuthConfig, /* your apps */],
SOCIALACCOUNT: {
  PROVIDERS: {
    github: { APP: { clientId: env.GITHUB_CLIENT_ID, secret: env.GITHUB_SECRET } },
    google: { APP: { clientId: env.GOOGLE_CLIENT_ID, secret: env.GOOGLE_SECRET } },
  },
},
```

```ts
// src/urls.ts
import { authUrls } from '@ghuri/auth'
import { socialUrls } from '@ghuri/socialauth'

export const urlpatterns = [
  path('accounts/', include(authUrls)),
  path('accounts/', include(socialUrls)),
]
```

```sh
npx ghuri migrate
```

Register `https://<your host>/accounts/<provider>/login/callback/` as the redirect URI in each provider's console.

A login button is a POST form (CSRF-protected, so other sites can't log your visitors in to their own account):

```html
<form method="post" action="/accounts/github/login/?next=/dashboard/">
  <input type="hidden" name="csrfmiddlewaretoken" value="{csrfToken}">
  <button>Continue with GitHub</button>
</form>
```

A GET to the same URL shows a one-button confirmation page instead (or starts right away with `LOGIN_ON_GET: true`).

## Providers

| id | Notes |
|---|---|
| `github` | Profile from `/user`; the email is the primary **verified** one from `/user/emails`. `settings.webUrl` / `apiUrl` for GitHub Enterprise. |
| `google` | OpenID Connect. |
| `facebook` | Graph API (`VERSION`, default `v21.0`). Emails are treated as unverified unless `VERIFIED_EMAIL: true`. |
| `microsoft` | Entra ID, OpenID Connect. `settings.tenant` (default `common`). Emails are never trusted by default (tenants can claim any address). |
| `discord` | `verified` flag from `/users/@me`. |
| `gitlab` | OpenID Connect; `settings.url` for self-hosted GitLab. |
| `openid_connect` | Any OIDC issuer (Auth0, Okta, Keycloak, Cognito, Zitadel…), several apps at once: |

```ts
openid_connect: {
  APPS: [
    { providerId: 'okta', name: 'Okta', clientId: env.OKTA_ID, secret: env.OKTA_SECRET, settings: { serverUrl: 'https://acme.okta.com' } },
  ],
},
// → /accounts/okta/login/
```

Per provider: `SCOPE` (replaces the defaults), `AUTH_PARAMS` (extra authorization parameters), `VERIFIED_EMAIL`.
Credentials can also live in the database as `SocialApp` rows (managed in the admin); settings win.

Your own provider: subclass `Provider`, return an `OAuth2Strategy` / `OIDCStrategy` from `createStrategy()`, and call
`registerProvider(new MyProvider())`.

## What happens on the callback

1. **A linked account** (`SocialAccount` with this provider and uid) → its user logs in.
2. **Connecting** (`?process=connect`, user logged in) → the account is linked to them. An account linked to someone
   else is refused.
3. **`EMAIL_AUTHENTICATION`** (off by default) and the provider says the email is **verified** and exactly one user has
   it → link and log in. Unverified emails never link to existing users.
4. **Sign up**: with `AUTO_SIGNUP` (default) the user is created from the profile (a free username, the email unless
   another user has it, first/last name) with an unusable password. When something is missing or taken, the visitor
   goes to `signup/` to fill it in.

Then: redirect to a safe `next` or `LOGIN_REDIRECT_URL`. Errors redirect to `LOGIN_ERROR_URL` (default `LOGIN_URL`)
with `?error=`.

## URLs

| | |
|---|---|
| `providers/` | JSON list of configured providers with their login URLs. |
| `<provider>/login/` | POST starts the login (`?next=`, `?process=connect`). |
| `<provider>/login/callback/` | The OAuth callback. |
| `<provider>/token/` | Native apps: POST JSON `{ id_token }` (OIDC providers) or `{ access_token }` (GitHub, Facebook). The token is checked against your client id (`settings.audiences` adds iOS/Android client ids). |
| `token/` | SPAs: POST JSON `{ code }` → `{ access, refresh, user }`. |
| `signup/` | Finish a signup (HTML form or JSON). |
| `connections/` | The user's linked accounts (GET); POST `{ account }` disconnects one. The last login method of a user without a password can't be removed. |

## SPAs and mobile apps

With `LOGIN_RESPONSE: 'jwt'` and `FRONTEND_URL`, the callback redirects to `FRONTEND_URL#code=<one-time code>`; the SPA
posts the code to `token/` for a JWT pair. Tokens never appear in URLs; codes expire after 60 seconds and are refused on
reuse while the cache remembers them. Native apps that sign in with the provider's SDK post the token to
`<provider>/token/` instead and get a session (or the JWT pair with `LOGIN_RESPONSE: 'jwt'`).

## Adapter and signals

```ts
import { ImmediateResponse, SocialAccountAdapter } from '@ghuri/socialauth'

class Adapter extends SocialAccountAdapter {
  isOpenForSignup(c, login) {
    return login.profile.email?.endsWith('@acme.com') ?? false
  }
  async preSocialLogin(c, login) {
    if (login.provider.id === 'facebook') throw new ImmediateResponse(c.text('Not here', 403))
  }
}

SOCIALACCOUNT: { ADAPTER: Adapter }
```

Also: `isAutoSignupAllowed`, `newUser`, `populateUser`, `saveUser`, `generateUsername`, `getConnectRedirectUrl`,
`authenticationError`. Signals: `preSocialLogin`, `socialAccountAdded`, `socialAccountUpdated`, `socialAccountRemoved`.

## Provider tokens

With `STORE_TOKENS: true`, access and refresh tokens are kept in `SocialToken`, encrypted with a key derived from
`SECRET_KEY`. `await getAccessToken(account)` returns a usable token, refreshing it when it expired.

## Admin

```ts
// src/admin.ts
import '@ghuri/socialauth/admin'   // SocialApp, SocialAccount, SocialToken (tokens are never shown)
```

## Settings

```ts
SOCIALACCOUNT: {
  PROVIDERS: {},
  ADAPTER: SocialAccountAdapter,
  AUTO_SIGNUP: true,
  EMAIL_AUTHENTICATION: false,
  EMAIL_REQUIRED: false,
  LOGIN_ON_GET: false,
  STORE_TOKENS: false,
  LOGIN_RESPONSE: 'session',     // or 'jwt' (needs FRONTEND_URL)
  FRONTEND_URL: undefined,
  LOGIN_ERROR_URL: undefined,    // default LOGIN_URL
}
```

## Testing

```ts
import { socialLogin } from '@ghuri/socialauth/testing'

const res = await socialLogin(client, 'github', { id: '1', username: 'ann', email: 'ann@example.com', emailVerified: true })
// the client is now logged in (or res redirects to signup/)
```

`socialLogin` runs the real views with a stand-in for the provider. To test a provider's own requests, use
`mockOAuthProvider` from `@ghuri/oauth/testing`.

## For django-allauth users

| allauth | Ghuri |
|---|---|
| `INSTALLED_APPS += ['allauth.socialaccount', 'allauth.socialaccount.providers.github']` | `SocialAuthConfig` (all providers built in) |
| `SOCIALACCOUNT_PROVIDERS = {'github': {'APP': {...}}}` | `SOCIALACCOUNT: { PROVIDERS: { github: { APP: { clientId, secret } } } }` |
| `{% provider_login_url 'github' %}` | `reverse('socialaccount_login', { provider: 'github' })` |
| `SOCIALACCOUNT_AUTO_SIGNUP`, `SOCIALACCOUNT_EMAIL_AUTHENTICATION`, `SOCIALACCOUNT_LOGIN_ON_GET`, `SOCIALACCOUNT_STORE_TOKENS` | `AUTO_SIGNUP`, `EMAIL_AUTHENTICATION`, `LOGIN_ON_GET`, `STORE_TOKENS` |
| `DefaultSocialAccountAdapter` | `SocialAccountAdapter` |
| `SocialAccount`, `SocialApp`, `SocialToken` (same tables) | same |
| allauth headless `provider/token` | `<provider>/token/` |
