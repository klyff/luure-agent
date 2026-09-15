const PRODUCTION_BASE_URL = 'https://agent.luure.com.br';
const DEV_BASE_URL = 'http://localhost:3100';
const defaultBaseUrl =
  process.env.BASE_URL ??
  (process.env.NODE_ENV === 'production' ? PRODUCTION_BASE_URL : DEV_BASE_URL);

/** client_id canônico da POC (Wallet SOU 2.0 ↔ agent.luure.com.br). */
export const POC_WALLET_CLIENT_ID = 'luure-wallet-sou20-gov-sp';

export function parseWalletClientIds(
  raw = process.env.WALLET_CLIENT_IDS,
): readonly string[] {
  if (!raw?.trim()) return [POC_WALLET_CLIENT_ID];
  const ids = raw
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean);
  return ids.length > 0 ? ids : [POC_WALLET_CLIENT_ID];
}

export const WALLET_CLIENT_IDS = parseWalletClientIds();

export const config = {
  port: Number(process.env.PORT ?? 3100),
  baseUrl: defaultBaseUrl,
  issuerId: process.env.ISSUER_ID ?? defaultBaseUrl,
  govbrIssuer: process.env.GOVBR_ISSUER ?? `${defaultBaseUrl}/govbr`,
  /** Clients registrados no ambiente vigente (default: POC). */
  walletClientIds: WALLET_CLIENT_IDS,
  walletClientId: WALLET_CLIENT_IDS[0] ?? POC_WALLET_CLIENT_ID,
  walletRedirectUris: [
    'sou20://govbr/callback',
    'sovereignid://govbr/callback',
    'luure://govbr/callback',
    'http://localhost:8081/govbr/callback',
  ],
} as const;

export function isAllowedWalletClientId(clientId: string | undefined): boolean {
  return (
    typeof clientId === 'string' &&
    (config.walletClientIds as readonly string[]).includes(clientId)
  );
}

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
