import { inflateSync } from 'node:zlib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import * as jose from 'jose';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { buildApp } from '../app.js';
import { prisma } from '../lib/db.js';
import { config } from '../lib/config.js';

const TEST_SERVIDOR = {
  cpf: '98765432100',
  nome: 'Beatriz Nogueira Lima',
  matricula: 'SEFAZ-990011',
  cargo: 'Analista de Finanças',
  orgao: 'SEFAZ-SP',
  secretaria: 'Secretaria da Fazenda e Planejamento',
  vinculoAtivo: true,
  dataAdmissao: new Date('2015-05-04T00:00:00.000Z'),
  fotoHash: 'hash-beatriz',
  margemDisponivelCentavos: 123400,
  nivelContaGovbr: 'ouro',
};

const TEST_SERVIDOR_INATIVO = {
  ...TEST_SERVIDOR,
  cpf: '11122233344',
  nome: 'Otávio Prado Inativo',
  matricula: 'PRODESP-000111',
  vinculoAtivo: false,
};

const VCT_FUNCIONAL = 'urn:sovereignid:sp:funcional';
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

let app: FastifyInstance;
let holderPrivateJwk: jose.JWK;
let holderPublicJwk: jose.JWK;
let holderSdJwt: SDJwtVcInstance;
/** Credencial SD-JWT VC emitida no beforeAll, reutilizada nos testes. */
let credential: string;

async function createOffer(vct: string, cpf = TEST_SERVIDOR.cpf) {
  const res = await app.inject({
    method: 'POST',
    url: '/issuer/credential-offers',
    payload: { cpf, vct },
  });
  return res;
}

async function getToken(preAuthorizedCode: string, txCode?: string) {
  const form = new URLSearchParams({
    grant_type: PRE_AUTH_GRANT,
    'pre-authorized_code': preAuthorizedCode,
  });
  if (txCode !== undefined) form.set('tx_code', txCode);
  return app.inject({
    method: 'POST',
    url: '/issuer/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: form.toString(),
  });
}

async function makeProofJwt(nonce: string, aud = config.baseUrl) {
  const holderKey = await jose.importJWK(holderPrivateJwk, 'ES256');
  return new jose.SignJWT({ nonce })
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'openid4vci-proof+jwt',
      jwk: holderPublicJwk,
    })
    .setAudience(aud)
    .setIssuedAt()
    .sign(holderKey);
}

async function issueCredential(vct: string): Promise<string> {
  const offerRes = await createOffer(vct);
  expect(offerRes.statusCode).toBe(200);
  const offer = offerRes.json();

  const tokenRes = await getToken(offer.pre_authorized_code, offer.tx_code);
  expect(tokenRes.statusCode).toBe(200);
  const token = tokenRes.json();

  const proofJwt = await makeProofJwt(token.c_nonce);
  const credRes = await app.inject({
    method: 'POST',
    url: '/issuer/credential',
    headers: { authorization: `Bearer ${token.access_token}` },
    payload: { vct, proof: { proof_type: 'jwt', jwt: proofJwt } },
  });
  expect(credRes.statusCode).toBe(200);
  return credRes.json().credentials[0].credential as string;
}

async function createSession(requestedClaims: string[], vct = VCT_FUNCIONAL) {
  const res = await app.inject({
    method: 'POST',
    url: '/verifier/sessions',
    payload: { vct, requested_claims: requestedClaims },
  });
  expect(res.statusCode).toBe(200);
  const session = res.json();
  const reqRes = await app.inject({
    method: 'GET',
    url: `/verifier/request/${session.id}`,
  });
  expect(reqRes.statusCode).toBe(200);
  return { session, request: reqRes.json() };
}

async function presentAndPost(
  cred: string,
  claims: Record<string, boolean>,
  kb: { aud: string; nonce: string; iat?: number },
  state: string,
) {
  const vpToken = await holderSdJwt.present(cred, claims, {
    kb: {
      payload: {
        aud: kb.aud,
        nonce: kb.nonce,
        iat: kb.iat ?? Math.floor(Date.now() / 1000),
      },
    },
  });
  return app.inject({
    method: 'POST',
    url: '/verifier/direct_post',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ vp_token: vpToken, state }).toString(),
  });
}

beforeAll(async () => {
  for (const servidor of [TEST_SERVIDOR, TEST_SERVIDOR_INATIVO]) {
    await prisma.servidor.upsert({
      where: { cpf: servidor.cpf },
      update: servidor,
      create: servidor,
    });
  }
  app = await buildApp();

  const { privateKey, publicKey } = await jose.generateKeyPair('ES256', {
    extractable: true,
  });
  holderPrivateJwk = await jose.exportJWK(privateKey);
  holderPublicJwk = await jose.exportJWK(publicKey);
  holderSdJwt = new SDJwtVcInstance({
    hasher: digest,
    saltGenerator: generateSalt,
    kbSigner: await ES256.getSigner(holderPrivateJwk),
    kbSignAlg: 'ES256',
  });

  credential = await issueCredential(VCT_FUNCIONAL);
});

afterAll(async () => {
  await app.close();
  await prisma.$disconnect();
});

describe('metadata OID4VCI', () => {
  it('well-known expõe as duas configurações dc+sd-jwt', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/.well-known/openid-credential-issuer',
    });
    expect(res.statusCode).toBe(200);
    const meta = res.json();
    expect(meta.credential_issuer).toBe(config.baseUrl);
    const configs = meta.credential_configurations_supported;
    expect(configs[VCT_FUNCIONAL].format).toBe('dc+sd-jwt');
    expect(configs['urn:sovereignid:sp:margem-consignavel'].format).toBe('dc+sd-jwt');
  });

  it('jwks.json expõe a chave pública do issuer', async () => {
    const res = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    expect(res.statusCode).toBe(200);
    const { keys } = res.json();
    expect(keys[0].kty).toBe('EC');
    expect(keys[0].d).toBeUndefined();
  });
});

describe('emissão OID4VCI (fluxo feliz)', () => {
  it('credencial emitida é um SD-JWT VC válido com cnf do holder', async () => {
    expect(credential.split('~').length).toBeGreaterThan(2);
    const jwtPart = credential.split('~')[0]!;
    const payload = jose.decodeJwt(jwtPart);
    expect(payload.vct).toBe(VCT_FUNCIONAL);
    expect(payload.iss).toBe(config.baseUrl);
    expect((payload.cnf as { jwk: jose.JWK }).jwk.x).toBe(holderPublicJwk.x);
    const status = payload.status as {
      status_list: { idx: number; uri: string };
    };
    expect(status.status_list.uri).toBe(`${config.baseUrl}/status/token-status-list`);
    // claims são seletivamente divulgáveis: não aparecem em claro no payload
    expect(payload.nome).toBeUndefined();
    expect(payload._sd).toBeDefined();
  });

  it('oferta para vct funcional exige vínculo ativo (422)', async () => {
    const res = await createOffer(VCT_FUNCIONAL, TEST_SERVIDOR_INATIVO.cpf);
    expect(res.statusCode).toBe(422);
    expect(res.json().error).toBe('vinculo_inativo');
  });

  it('proof com nonce errado retorna 400 invalid_proof', async () => {
    const offer = (await createOffer(VCT_FUNCIONAL)).json();
    const token = (await getToken(offer.pre_authorized_code)).json();
    const badProof = await makeProofJwt('nonce-completamente-errado');
    const res = await app.inject({
      method: 'POST',
      url: '/issuer/credential',
      headers: { authorization: `Bearer ${token.access_token}` },
      payload: {
        vct: VCT_FUNCIONAL,
        proof: { proof_type: 'jwt', jwt: badProof },
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_proof');
  });

  it('tx_code errado no token retorna invalid_grant', async () => {
    const offer = (await createOffer(VCT_FUNCIONAL)).json();
    const res = await getToken(offer.pre_authorized_code, '0000');
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_grant');
  });
});

describe('apresentação OID4VP (fluxo feliz + privacidade)', () => {
  it('apresenta só nome+cargo e a sessão fica verified com essas claims', async () => {
    const { session, request } = await createSession(['nome', 'cargo']);
    expect(request.response_mode).toBe('direct_post');
    expect(request.dcql_query.credentials[0].meta.vct_values).toEqual([VCT_FUNCIONAL]);
    expect(request.dcql_query.credentials[0].claims).toEqual([
      { path: ['nome'] },
      { path: ['cargo'] },
    ]);

    const res = await presentAndPost(
      credential,
      { nome: true, cargo: true },
      { aud: request.client_id, nonce: request.nonce },
      request.state,
    );
    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('verified');

    const poll = await app.inject({
      method: 'GET',
      url: `/verifier/sessions/${session.id}`,
    });
    const result = poll.json();
    expect(result.status).toBe('verified');
    expect(result.claims.nome).toBe(TEST_SERVIDOR.nome);
    expect(result.claims.cargo).toBe(TEST_SERVIDOR.cargo);
    // privacidade: claims não divulgadas não aparecem no resultado
    expect(result.claims.cpf_mascarado).toBeUndefined();
    expect(result.claims.matricula).toBeUndefined();
    expect(result.claims.foto_hash).toBeUndefined();
  });

  it('nonce de sessão errado no KB-JWT → rejected', async () => {
    const { session, request } = await createSession(['nome']);
    const res = await presentAndPost(
      credential,
      { nome: true },
      { aud: request.client_id, nonce: 'nonce-de-outra-sessao' },
      request.state,
    );
    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('rejected');

    const poll = await app.inject({
      method: 'GET',
      url: `/verifier/sessions/${session.id}`,
    });
    expect(poll.json().status).toBe('rejected');
    expect(poll.json().reason).toContain('apresentacao_invalida');
  });

  it('sessão é single-use: segundo direct_post é recusado', async () => {
    const { request } = await createSession(['nome']);
    const first = await presentAndPost(
      credential,
      { nome: true },
      { aud: request.client_id, nonce: request.nonce },
      request.state,
    );
    expect(first.json().status).toBe('verified');

    const second = await presentAndPost(
      credential,
      { nome: true },
      { aud: request.client_id, nonce: request.nonce },
      request.state,
    );
    expect(second.statusCode).toBe(400);
    expect(second.json().error).toBe('session_already_used');
  });
});

describe('revogação / status list', () => {
  it('credencial revogada → rejected e bit 1 na status list', async () => {
    const jwtPart = credential.split('~')[0]!;
    const payload = jose.decodeJwt(jwtPart);
    const idx = (payload.status as { status_list: { idx: number } }).status_list.idx;

    const issued = await prisma.credentialIssued.findUnique({
      where: { statusListIndex: idx },
    });
    expect(issued).toBeTruthy();

    const revokeRes = await app.inject({
      method: 'POST',
      url: '/admin/revoke',
      payload: { credential_id: issued!.id },
    });
    expect(revokeRes.statusCode).toBe(200);
    expect(revokeRes.json().revoked).toBe(true);

    // apresentação da credencial revogada é rejeitada
    const { request } = await createSession(['nome']);
    const res = await presentAndPost(
      credential,
      { nome: true },
      { aud: request.client_id, nonce: request.nonce },
      request.state,
    );
    expect(res.json()).toEqual({
      status: 'rejected',
      reason: 'credencial_revogada',
    });

    // status list JWT reflete o bit de revogação
    const slRes = await app.inject({ method: 'GET', url: '/status/token-status-list' });
    expect(slRes.statusCode).toBe(200);
    expect(slRes.headers['content-type']).toContain('application/statuslist+jwt');
    const slPayload = jose.decodeJwt(slRes.body) as {
      status_list: { bits: number; lst: string };
    };
    expect(slPayload.status_list.bits).toBe(1);
    const bitstring = inflateSync(Buffer.from(slPayload.status_list.lst, 'base64url'));
    const bit = (bitstring[Math.floor(idx / 8)]! >> idx % 8) & 1;
    expect(bit).toBe(1);
  });
});
