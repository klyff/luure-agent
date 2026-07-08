import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import type { JwtPayload, KbVerifier, Signer, Verifier } from '@sd-jwt/core';
import { getIssuerKeys } from './keys.js';

export const VCT_FUNCIONAL = 'urn:sovereignid:sp:funcional';
export const VCT_MARGEM = 'urn:sovereignid:sp:margem-consignavel';
export const SUPPORTED_VCTS = [VCT_FUNCIONAL, VCT_MARGEM] as const;

export const CLAIMS_BY_VCT: Record<string, string[]> = {
  [VCT_FUNCIONAL]: [
    'nome',
    'cpf_mascarado',
    'matricula',
    'cargo',
    'orgao',
    'secretaria',
    'vinculo_ativo',
    'data_admissao',
    'foto_hash',
  ],
  [VCT_MARGEM]: [
    'matricula',
    'margem_disponivel_centavos',
    'faixa_margem',
    'competencia',
  ],
};

export function faixaMargem(centavos: number): string {
  if (centavos <= 50_000) return 'ATE_500';
  if (centavos <= 150_000) return '500_A_1500';
  return 'ACIMA_1500';
}

let issuerSigner: Signer | undefined;
let issuerVerifier: Verifier | undefined;

async function getIssuerSigner(): Promise<Signer> {
  if (!issuerSigner) {
    issuerSigner = await ES256.getSigner(getIssuerKeys().privateJwk);
  }
  return issuerSigner;
}

export async function getIssuerVerifier(): Promise<Verifier> {
  if (!issuerVerifier) {
    issuerVerifier = await ES256.getVerifier(getIssuerKeys().publicJwk);
  }
  return issuerVerifier;
}

/** Instância para EMISSÃO de SD-JWT VC assinada pela chave do issuer. */
export async function createIssuerInstance(): Promise<SDJwtVcInstance> {
  return new SDJwtVcInstance({
    signer: await getIssuerSigner(),
    signAlg: 'ES256',
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });
}

/** Valida assinatura do KB-JWT com a chave pública do holder em cnf.jwk. */
const kbVerifier: KbVerifier = async (data, sig, payload: JwtPayload) => {
  if (!payload.cnf?.jwk) return false;
  const verify = await ES256.getVerifier(payload.cnf.jwk);
  return verify(data, sig);
};

/** Instância para VERIFICAÇÃO de apresentações (assinatura issuer + KB-JWT). */
export async function createVerifierInstance(): Promise<SDJwtVcInstance> {
  return new SDJwtVcInstance({
    verifier: await getIssuerVerifier(),
    kbVerifier,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });
}
