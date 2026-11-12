# Changelog

## 0.1.0-alpha.0

- Initial alpha (ARCHITECTURE.md §18).
- `SocialAuthConfig` with allauth's `SocialApp`, `SocialAccount`, `SocialToken` (encrypted) and migrations that follow
  `AUTH_USER_MODEL`.
- Providers: GitHub, Google, Facebook, Microsoft, Discord, GitLab, generic OpenID Connect (several apps);
  `registerProvider()` for your own.
- The login flow: existing links, connect, verified-email linking (opt-in), auto signup with a signup form fallback;
  `SocialAccountAdapter`, `ImmediateResponse`, signals.
- URLs: providers list, login (POST, confirm page on GET), callback, native-token login, SPA one-time code exchange,
  signup, connections (disconnect with a last-login-method guard).
- `@ghuri/socialauth/admin`, `@ghuri/socialauth/testing` (`socialLogin`).
