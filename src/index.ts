export { getAdapter, ImmediateResponse, type SignupData, SocialAccountAdapter } from './adapter'
export { SocialAuthConfig } from './apps'
export {
  buildLogin,
  completeSocialLogin,
  finishLogin,
  type Mode,
  makeLoginCode,
  type Process,
  redeemLoginCode,
  SocialAuthError,
  type SocialLogin,
} from './login'
export { emptyDict, SocialAccount, SocialApp, SocialToken } from './models'
export {
  allProviders,
  DiscordProvider,
  FacebookProvider,
  GitHubProvider,
  GitLabProvider,
  GoogleProvider,
  getProvider,
  MicrosoftProvider,
  OpenIDConnectProvider,
  Provider,
  registerProvider,
  type StrategyContext,
} from './providers'
export { configuredProviders, type ResolvedProvider, resolveProvider } from './resolve'
export {
  type AppSettings,
  type ProviderSettings,
  type ResolvedSocialSettings,
  type SocialAccountSettings,
  socialSettings,
} from './settings'
export { preSocialLogin, socialAccountAdded, socialAccountRemoved, socialAccountUpdated } from './signals'
export { getAccessToken, storeTokens } from './tokens'
export {
  callbackView,
  connectionsView,
  loginView,
  nativeTokenView,
  providersView,
  signupView,
  socialUrls,
  tokenExchangeView,
} from './views'
