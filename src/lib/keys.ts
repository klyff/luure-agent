import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import * as jose from 'jose';

const KEYS_DIR = path.resolve(process.cwd(), 'keys');

export interface KeyPair {
  privateKey: jose.CryptoKey;
  publicKey: jose.CryptoKey;
  privateJwk: jose.JWK;
  publicJwk: jose.JWK;
  kid: string;
}

async function importPair(jwk: jose.JWK): Promise<KeyPair> {
  const privateKey = (await jose.importJWK(jwk, 'ES256')) as jose.CryptoKey;
  const { d: _d, ...publicJwk } = jwk;
  const publicKey = (await jose.importJWK(publicJwk, 'ES256')) as jose.CryptoKey;
  return {
    privateKey,
    publicKey,
    privateJwk: jwk,
    publicJwk,
    kid: jwk.kid ?? '',
  };
}

/**
 * Origem das chaves, em ordem de precedência:
 * 1. Env var (ISSUER_JWK / GOVBR_JWK) — obrigatório em produção/serverless,
 *    onde o filesystem é efêmero.
 * 2. Arquivo em keys/ — conveniência de desenvolvimento local (gera na
 *    primeira execução).
 */
async function loadOrCreateKeyPair(
  envVar: string,
  fileName: string,
): Promise<KeyPair> {
  const fromEnv = process.env[envVar];
  if (fromEnv) {
    return importPair(JSON.parse(fromEnv) as jose.JWK);
  }
  if (process.env.VERCEL || process.env.NODE_ENV === 'production') {
    throw new Error(`${envVar} é obrigatório em produção (JWK privada ES256 em JSON)`);
  }

  const filePath = path.join(KEYS_DIR, fileName);
  let jwk: jose.JWK;
  if (existsSync(filePath)) {
    jwk = JSON.parse(readFileSync(filePath, 'utf-8')) as jose.JWK;
  } else {
    const { privateKey } = await jose.generateKeyPair('ES256', {
      extractable: true,
    });
    jwk = await jose.exportJWK(privateKey);
    jwk.alg = 'ES256';
    jwk.use = 'sig';
    jwk.kid = await jose.calculateJwkThumbprint(jwk);
    mkdirSync(KEYS_DIR, { recursive: true });
    writeFileSync(filePath, JSON.stringify(jwk, null, 2));
  }
  return importPair(jwk);
}

let issuerKeys: KeyPair | undefined;
let govbrKeys: KeyPair | undefined;

export async function initKeys(): Promise<void> {
  issuerKeys = await loadOrCreateKeyPair('ISSUER_JWK', 'issuer.jwk.json');
  govbrKeys = await loadOrCreateKeyPair('GOVBR_JWK', 'govbr.jwk.json');
}

export function getIssuerKeys(): KeyPair {
  if (!issuerKeys) throw new Error('Keys not initialized — call initKeys() first');
  return issuerKeys;
}

export function getGovbrKeys(): KeyPair {
  if (!govbrKeys) throw new Error('Keys not initialized — call initKeys() first');
  return govbrKeys;
}
