import { createHash, randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { customAlphabet, nanoid } from 'nanoid';
import QRCode from 'qrcode';
import * as jose from 'jose';
import type { DisclosureFrame } from '@sd-jwt/core';
import { prisma } from '../../lib/db.js';
import { ephemeralGet, ephemeralSet } from '../../lib/ephemeral.js';
import { config } from '../../lib/config.js';
import { getIssuerKeys } from '../../lib/keys.js';
import {
  CLAIMS_BY_VCT,
  SUPPORTED_VCTS,
  VCT_FUNCIONAL,
  VCT_MARGEM,
  createIssuerInstance,
  faixaMargem,
} from '../../lib/sdjwt.js';
import { maskCpf } from '../sou-sp/routes.js';
import type { ServidorModel } from '../../generated/prisma/models.js';

const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const OFFER_TTL_MS = 10 * 60 * 1000;
const TOKEN_TTL_SECONDS = 600;

const txCodeGen = customAlphabet('0123456789', 4);

interface AccessTokenData {
  cpf: string;
  vct: string;
  cNonce: string;
}

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

// Tokens opacos persistidos por hash sha256 no armazenamento efêmero do banco
// (serverless: instâncias diferentes atendem /token e /credential).
export async function lookupAccessToken(
  token: string,
): Promise<AccessTokenData | undefined> {
  return ephemeralGet<AccessTokenData>(`issuer:token:${sha256(token)}`);
}

function buildClaims(
  vct: string,
  servidor: ServidorModel,
): Record<string, unknown> {
  if (vct === VCT_FUNCIONAL) {
    return {
      nome: servidor.nome,
      cpf_mascarado: maskCpf(servidor.cpf),
      matricula: servidor.matricula,
      cargo: servidor.cargo,
      orgao: servidor.orgao,
      secretaria: servidor.secretaria,
      vinculo_ativo: servidor.vinculoAtivo,
      data_admissao: servidor.dataAdmissao.toISOString().slice(0, 10),
      foto_hash: servidor.fotoHash,
    };
  }
  return {
    matricula: servidor.matricula,
    margem_disponivel_centavos: servidor.margemDisponivelCentavos,
    faixa_margem: faixaMargem(servidor.margemDisponivelCentavos),
    competencia: new Date().toISOString().slice(0, 7),
  };
}

async function nextStatusListIndex(): Promise<number> {
  const agg = await prisma.credentialIssued.aggregate({
    _max: { statusListIndex: true },
  });
  return (agg._max.statusListIndex ?? -1) + 1;
}

export async function issuerRoutes(app: FastifyInstance): Promise<void> {
  const { baseUrl } = config;

  app.get('/.well-known/openid-credential-issuer', async () => ({
    credential_issuer: baseUrl,
    credential_endpoint: `${baseUrl}/issuer/credential`,
    token_endpoint: `${baseUrl}/issuer/token`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    credential_configurations_supported: {
      [VCT_FUNCIONAL]: {
        format: 'dc+sd-jwt',
        vct: VCT_FUNCIONAL,
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: {
          jwt: { proof_signing_alg_values_supported: ['ES256'] },
        },
        claims: CLAIMS_BY_VCT[VCT_FUNCIONAL]?.map((c) => ({ path: [c] })),
        display: [
          {
            name: 'Carteira Funcional Digital SP',
            locale: 'pt-BR',
            background_color: '#1351B4',
            text_color: '#FFFFFF',
          },
        ],
      },
      [VCT_MARGEM]: {
        format: 'dc+sd-jwt',
        vct: VCT_MARGEM,
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: {
          jwt: { proof_signing_alg_values_supported: ['ES256'] },
        },
        claims: CLAIMS_BY_VCT[VCT_MARGEM]?.map((c) => ({ path: [c] })),
        display: [
          {
            name: 'Margem Consignável SP',
            locale: 'pt-BR',
            background_color: '#168821',
            text_color: '#FFFFFF',
          },
        ],
      },
    },
  }));

  app.get('/.well-known/jwks.json', async () => ({
    keys: [getIssuerKeys().publicJwk],
  }));

  app.post<{ Body: { cpf?: string; vct?: string } }>(
    '/issuer/credential-offers',
    async (request, reply) => {
      const { cpf, vct } = request.body ?? {};
      if (!cpf || !vct) {
        return reply.code(400).send({
          error: 'invalid_request',
          error_description: 'cpf e vct são obrigatórios',
        });
      }
      if (!SUPPORTED_VCTS.includes(vct as (typeof SUPPORTED_VCTS)[number])) {
        return reply.code(400).send({
          error: 'unsupported_credential_type',
          error_description: `vct não suportado: ${vct}`,
        });
      }
      const servidor = await prisma.servidor.findUnique({ where: { cpf } });
      if (!servidor) {
        return reply.code(404).send({
          error: 'servidor_nao_encontrado',
          error_description: 'CPF não consta na base SOU.SP',
        });
      }
      if (vct === VCT_FUNCIONAL && !servidor.vinculoAtivo) {
        return reply.code(422).send({ error: 'vinculo_inativo' });
      }

      const offer = await prisma.credentialOffer.create({
        data: {
          preAuthorizedCode: nanoid(),
          txCode: txCodeGen(),
          vct,
          servidorCpf: cpf,
          status: 'pending',
          expiresAt: new Date(Date.now() + OFFER_TTL_MS),
        },
      });

      const credentialOfferUri = `${baseUrl}/issuer/credential-offer/${offer.id}`;
      const offerDeeplink = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(credentialOfferUri)}`;
      const qrcodePngBase64 = await QRCode.toDataURL(offerDeeplink);

      return {
        id: offer.id,
        credential_offer_uri: credentialOfferUri,
        offer_deeplink: offerDeeplink,
        qrcode_png_base64: qrcodePngBase64,
        pre_authorized_code: offer.preAuthorizedCode,
        tx_code: offer.txCode,
      };
    },
  );

  app.get<{ Params: { id: string } }>(
    '/issuer/credential-offer/:id',
    async (request, reply) => {
      const offer = await prisma.credentialOffer.findUnique({
        where: { id: request.params.id },
      });
      if (!offer) {
        return reply.code(404).send({ error: 'offer_not_found' });
      }
      return {
        credential_issuer: baseUrl,
        credential_configuration_ids: [offer.vct],
        grants: {
          [PRE_AUTH_GRANT]: {
            'pre-authorized_code': offer.preAuthorizedCode,
            tx_code: {
              length: 4,
              input_mode: 'numeric',
              description: 'Código exibido no portal do emissor',
            },
          },
        },
      };
    },
  );

  app.post<{
    Body: {
      grant_type?: string;
      'pre-authorized_code'?: string;
      tx_code?: string;
    };
  }>('/issuer/token', async (request, reply) => {
    const body = request.body ?? {};
    if (body.grant_type !== PRE_AUTH_GRANT) {
      return reply.code(400).send({
        error: 'unsupported_grant_type',
        error_description: `grant_type deve ser ${PRE_AUTH_GRANT}`,
      });
    }
    const code = body['pre-authorized_code'];
    if (!code) {
      return reply.code(400).send({
        error: 'invalid_request',
        error_description: 'pre-authorized_code é obrigatório',
      });
    }
    const offer = await prisma.credentialOffer.findUnique({
      where: { preAuthorizedCode: code },
    });
    if (!offer || offer.status !== 'pending') {
      return reply.code(400).send({ error: 'invalid_grant' });
    }
    if (offer.expiresAt.getTime() < Date.now()) {
      await prisma.credentialOffer.update({
        where: { id: offer.id },
        data: { status: 'expired' },
      });
      return reply.code(400).send({ error: 'invalid_grant' });
    }
    // tx_code é opcional na PoC — mas se enviado, precisa conferir
    if (body.tx_code !== undefined && body.tx_code !== offer.txCode) {
      return reply.code(400).send({ error: 'invalid_grant' });
    }

    await prisma.credentialOffer.update({
      where: { id: offer.id },
      data: { status: 'claimed' },
    });

    const accessToken = randomBytes(32).toString('base64url');
    const cNonce = nanoid();
    await ephemeralSet(
      `issuer:token:${sha256(accessToken)}`,
      { cpf: offer.servidorCpf, vct: offer.vct, cNonce } satisfies AccessTokenData,
      TOKEN_TTL_SECONDS * 1000,
    );

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: TOKEN_TTL_SECONDS,
      c_nonce: cNonce,
    };
  });

  app.post<{
    Body: { vct?: string; proof?: { proof_type?: string; jwt?: string } };
  }>('/issuer/credential', async (request, reply) => {
    const auth = request.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      return reply.code(401).send({ error: 'invalid_token' });
    }
    const tokenData = await lookupAccessToken(auth.slice('Bearer '.length));
    if (!tokenData) {
      return reply.code(401).send({ error: 'invalid_token' });
    }

    const { vct, proof } = request.body ?? {};
    if (!vct || vct !== tokenData.vct) {
      return reply.code(400).send({
        error: 'unsupported_credential_type',
        error_description: 'vct ausente ou diferente do autorizado no token',
      });
    }
    if (proof?.proof_type !== 'jwt' || !proof.jwt) {
      return reply.code(400).send({
        error: 'invalid_proof',
        error_description: 'proof.proof_type deve ser "jwt" com campo jwt',
      });
    }

    // Valida o proof JWT: assinatura da chave do holder (jwk no header),
    // aud = credential_issuer e nonce = c_nonce do access token.
    let holderJwk: jose.JWK;
    try {
      const header = jose.decodeProtectedHeader(proof.jwt);
      // FINDINGS A-12: alg restrito a ES256 e typ do perfil OID4VCI exigido.
      if (header.alg !== 'ES256') throw new Error('alg deve ser ES256');
      if (header.typ !== 'openid4vci-proof+jwt') {
        throw new Error('typ deve ser openid4vci-proof+jwt');
      }
      if (!header.jwk) throw new Error('header.jwk ausente');
      holderJwk = header.jwk as jose.JWK;
      const holderKey = await jose.importJWK(holderJwk, 'ES256');
      const { payload } = await jose.jwtVerify(proof.jwt, holderKey, {
        audience: config.baseUrl,
        algorithms: ['ES256'],
      });
      if (payload.nonce !== tokenData.cNonce) {
        throw new Error('nonce diferente do c_nonce');
      }
      if (typeof payload.iat !== 'number') {
        throw new Error('iat ausente no proof');
      }
    } catch {
      return reply.code(400).send({ error: 'invalid_proof' });
    }

    const servidor = await prisma.servidor.findUnique({
      where: { cpf: tokenData.cpf },
    });
    if (!servidor) {
      return reply.code(400).send({ error: 'invalid_request' });
    }

    const claims = buildClaims(vct, servidor);
    const statusListIndex = await nextStatusListIndex();
    // Registro criado antes da emissão para que o id sirva de jti na credencial
    // (permite à wallet referenciar a credencial em /admin/revoke).
    const issuedRecord = await prisma.credentialIssued.create({
      data: {
        vct,
        servidorCpf: servidor.cpf,
        statusListIndex,
        sdJwtHash: '',
      },
    });
    const sdjwt = await createIssuerInstance();
    const payload = {
      vct,
      iss: config.baseUrl,
      iat: Math.floor(Date.now() / 1000),
      jti: issuedRecord.id,
      cnf: { jwk: holderJwk },
      // Claim "status" NÃO seletivamente divulgável (revogação verificável)
      status: {
        status_list: {
          idx: statusListIndex,
          uri: `${config.baseUrl}/status/token-status-list`,
        },
      },
      ...claims,
    };
    const credential = await sdjwt.issue(
      payload,
      { _sd: Object.keys(claims) } as DisclosureFrame<typeof payload>,
      { header: { kid: getIssuerKeys().kid } },
    );

    await prisma.credentialIssued.update({
      where: { id: issuedRecord.id },
      data: { sdJwtHash: sha256(credential.split('~')[0] ?? credential) },
    });

    return { credentials: [{ credential }] };
  });
}
