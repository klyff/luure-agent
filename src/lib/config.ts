const PRODUCTION_BASE_URL = 'https://agent.luure.com.br';
const DEV_BASE_URL = 'http://localhost:3100';
const defaultBaseUrl =
  process.env.BASE_URL ??
  (process.env.NODE_ENV === 'production' ? PRODUCTION_BASE_URL : DEV_BASE_URL);

export const config = {
  port: Number(process.env.PORT ?? 3100),
  baseUrl: defaultBaseUrl,
  issuerId: process.env.ISSUER_ID ?? defaultBaseUrl,
  govbrIssuer: process.env.GOVBR_ISSUER ?? `${defaultBaseUrl}/govbr`,
  // Wallet OAuth client id; luure-wallet is an alias for the same mobile app.
  walletClientId: 'sovereignid-wallet',
  walletRedirectUris: [
    'sovereignid://govbr/callback',
    'luure://govbr/callback',
    'http://localhost:8081/govbr/callback',
  ],
} as const;

// Expo Go (dev) usa redirect dinâmico exp://<host>:<porta>/--/govbr/callback.
// Aceito em dev e, na PoC hospedada, quando ALLOW_EXPO_REDIRECT=1 (a wallet
// ainda roda via Expo Go); um build nativo usa o scheme fixo da allowlist.
const EXPO_GO_REDIRECT = /^exp:\/\/[\w.:-]+\/--\/govbr\/callback$/;

export function isAllowedWalletRedirectUri(uri: string): boolean {
  if ((config.walletRedirectUris as readonly string[]).includes(uri)) return true;
  const expoAllowed =
    process.env.NODE_ENV !== 'production' ||
    process.env.ALLOW_EXPO_REDIRECT === '1';
  return expoAllowed && EXPO_GO_REDIRECT.test(uri);
}
