/**
 * QA Onda 3 — testes de segurança que materializam os itens do
 * docs/security/CHECKLIST_ONDA2.md que ainda não tinham teste automatizado.
 *
 * Mapa item do checklist → teste (describe/it) neste arquivo:
 * - (a) proof JWT de emissão .... "proof assinado por chave diferente da declarada"
 *                                 "proof com alg none", "pre-authorized_code é single-use"
 * - (a)/(b do enunciado) ........ "reuso de access_token" + "c_nonce antigo com token novo"
 * - (b) KB-JWT .................. "KB-JWT com aud errado", "KB-JWT com iat fora da janela"
 * - (b)/sd_hash ................. "disclosure adulterada"
 * - (g) assinatura do issuer .... "SD-JWT assinado por issuer falso"
 * - extras (FINDINGS A-01/A-02) . "redirect_uri fora da allowlist", "XSS refletido no state"
 *
 * Segue os padrões de oid4vc.test.ts (test.db, fastify inject, helpers duplicados
 * — os arquivos existentes não podem ser editados pela QA).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import * as jose from 'jose';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { buildApp } from '../app.js';
import { prisma } from '../lib/db.js';
import { config } from '../lib/config.js';

const TEST_SERVIDOR = {
  cpf: '55566677788',
  nome: 'Quitéria Alves de Souza',
  matricula: 'QA-ONDA3-0001',
  cargo: 'Analista de Qualidade',
  orgao: 'PRODESP',
  secretaria: 'Secretaria de Gestão e Governo Digital',
  vinculoAtivo: true,
  dataAdmissao: new Date('2018-01-10T00:00:00.000Z'),
  fotoHash: 'hash-quiteria',
  margemDisponivelCentavos: 100000,
  nivelContaGovbr: 'ouro',
};

const VCT_FUNCIONAL = 'urn:luure:sp:funcional';
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

let app: FastifyInstance;
let holderPrivateJwk: jose.JWK;
let holderPublicJwk: jose.JWK;
let holderSdJwt: SDJwtVcInstance;
/** Credencial legítima emitida no beforeAll, reutilizada nos testes de apresentação. */
let credential: string;

// ---------------------------------------------------------------------------
// Helpers (mesmo padrão de oid4vc.test.ts)
// ---------------------------------------------------------------------------

async function createOffer(vct: string, cpf = TEST_SERVIDOR.cpf) {
  return app.inject({
    method: 'POST',
    url: '/issuer/credential-offers',
    payload: { cpf, vct },
  });
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

interface ProofOptions {
  /** JWK privada que efetivamente assina (default: chave do holder). */
  signWith?: jose.JWK;
  /** JWK pública declarada no header.jwk (default: pública do holder). */
  declareJwk?: jose.JWK;
  aud?: string;
}

async function makeProofJwt(nonce: string, opts: ProofOptions = {}) {
  const signKey = await jose.importJWK(opts.signWith ?? holderPrivateJwk, 'ES256');
  return new jose.SignJWT({ nonce })
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'openid4vci-proof+jwt',
      jwk: opts.declareJwk ?? holderPublicJwk,
    })
    .setAudience(opts.aud ?? config.baseUrl)
    .setIssuedAt()
    .sign(signKey);
}

async function postCredential(accessToken: string, proofJwt: string, vct = VCT_FUNCIONAL) {
  return app.inject({
    method: 'POST',
    url: '/issuer/credential',
    headers: { authorization: `Bearer ${accessToken}` },
    payload: { vct, proof: { proof_type: 'jwt', jwt: proofJwt } },
  });
}

/** Fluxo feliz completo: oferta → token → proof → credencial. */
async function issueCredential(vct: string): Promise<string> {
  const offer = (await createOffer(vct)).json();
  const tokenRes = await getToken(offer.pre_authorized_code, offer.tx_code);
  expect(tokenRes.statusCode).toBe(200);
  const token = tokenRes.json();
  const proofJwt = await makeProofJwt(token.c_nonce);
  const credRes = await postCredential(token.access_token, proofJwt, vct);
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

async function directPost(vpToken: string, state: string) {
  return app.inject({
    method: 'POST',
    url: '/verifier/direct_post',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ vp_token: vpToken, state }).toString(),
  });
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
  return directPost(vpToken, state);
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeAll(async () => {
  await prisma.servidor.upsert({
    where: { cpf: TEST_SERVIDOR.cpf },
    update: TEST_SERVIDOR,
    create: TEST_SERVIDOR,
  });
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

// ---------------------------------------------------------------------------
// (a) Proof JWT de emissão — POST /issuer/credential
// ---------------------------------------------------------------------------

describe('emissão: proof JWT (checklist a)', () => {
  it('proof assinado por chave diferente da declarada no header.jwk → invalid_proof', async () => {
    const offer = (await createOffer(VCT_FUNCIONAL)).json();
    const token = (await getToken(offer.pre_authorized_code)).json();

    // Atacante assina com a chave DELE mas declara a JWK pública do holder
    // no header — a assinatura não confere com a chave declarada.
    const attacker = await jose.generateKeyPair('ES256', { extractable: true });
    const attackerPrivateJwk = await jose.exportJWK(attacker.privateKey);
    const forgedProof = await makeProofJwt(token.c_nonce, {
      signWith: attackerPrivateJwk,
      declareJwk: holderPublicJwk,
    });

    const res = await postCredential(token.access_token, forgedProof);
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_proof');
  });

  it('proof com aud diferente do credential_issuer → invalid_proof', async () => {
    const offer = (await createOffer(VCT_FUNCIONAL)).json();
    const token = (await getToken(offer.pre_authorized_code)).json();
    const proof = await makeProofJwt(token.c_nonce, { aud: 'https://issuer-malicioso.example' });
    const res = await postCredential(token.access_token, proof);
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_proof');
  });

  it('proof com alg none (JWT sem assinatura) → invalid_proof', async () => {
    const offer = (await createOffer(VCT_FUNCIONAL)).json();
    const token = (await getToken(offer.pre_authorized_code)).json();

    const b64 = (obj: unknown) =>
      Buffer.from(JSON.stringify(obj)).toString('base64url');
    const unsigned = `${b64({ alg: 'none', typ: 'openid4vci-proof+jwt', jwk: holderPublicJwk })}.${b64({
      nonce: token.c_nonce,
      aud: config.baseUrl,
      iat: Math.floor(Date.now() / 1000),
    })}.`;

    const res = await postCredential(token.access_token, unsigned);
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_proof');
  });

  it('pre-authorized_code é single-use: segunda troca por token → invalid_grant', async () => {
    const offer = (await createOffer(VCT_FUNCIONAL)).json();
    const first = await getToken(offer.pre_authorized_code, offer.tx_code);
    expect(first.statusCode).toBe(200);

    const second = await getToken(offer.pre_authorized_code, offer.tx_code);
    expect(second.statusCode).toBe(400);
    expect(second.json().error).toBe('invalid_grant');
  });
});

describe('emissão: reuso de access_token e c_nonce (checklist a / item b da QA)', () => {
  it('DOCUMENTADO: o design atual PERMITE reuso do access_token dentro do TTL (c_nonce não é rotacionado)', async () => {
    // O checklist pede c_nonce single-use, mas o código atual (issuer/routes.ts)
    // mantém o par access_token/c_nonce válido até o TTL de 600s e não o
    // invalida após a emissão. Este teste DOCUMENTA o comportamento vigente
    // como risco aceito da PoC: se ele passar a falhar, o design mudou para
    // single-use e o CHECKLIST_ONDA2 item (a) pode ser marcado como coberto.
    const offer = (await createOffer(VCT_FUNCIONAL)).json();
    const token = (await getToken(offer.pre_authorized_code)).json();
    const proof = await makeProofJwt(token.c_nonce);

    const first = await postCredential(token.access_token, proof);
    expect(first.statusCode).toBe(200);

    // Replay do MESMO proof com o MESMO access_token após sucesso.
    const replay = await postCredential(token.access_token, proof);
    expect(replay.statusCode).toBe(200); // comportamento atual (risco aceito na PoC)
  });

  it('c_nonce de token antigo não é aceito com access_token novo → invalid_proof', async () => {
    const offerA = (await createOffer(VCT_FUNCIONAL)).json();
    const tokenA = (await getToken(offerA.pre_authorized_code)).json();

    const offerB = (await createOffer(VCT_FUNCIONAL)).json();
    const tokenB = (await getToken(offerB.pre_authorized_code)).json();

    // Proof "antigo" (nonce do token A) enviado com o token novo (B):
    // o c_nonce é por-token, então tem que ser recusado.
    expect(tokenA.c_nonce).not.toBe(tokenB.c_nonce);
    const staleProof = await makeProofJwt(tokenA.c_nonce);
    const res = await postCredential(tokenB.access_token, staleProof);
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_proof');
  });
});

// ---------------------------------------------------------------------------
// (b) KB-JWT — POST /verifier/direct_post
// ---------------------------------------------------------------------------

describe('apresentação: KB-JWT (checklist b)', () => {
  it('KB-JWT com aud errado → rejected', async () => {
    const { session, request } = await createSession(['nome']);
    const res = await presentAndPost(
      credential,
      { nome: true },
      { aud: 'https://verificador-malicioso.example', nonce: request.nonce },
      request.state,
    );
    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('rejected');
    expect(res.json().reason).toBe('kb_aud_invalido');

    const poll = await app.inject({
      method: 'GET',
      url: `/verifier/sessions/${session.id}`,
    });
    expect(poll.json().status).toBe('rejected');
  });

  it('KB-JWT com iat 10 minutos no passado → rejected', async () => {
    const { request } = await createSession(['nome']);
    const res = await presentAndPost(
      credential,
      { nome: true },
      {
        aud: request.client_id,
        nonce: request.nonce,
        iat: Math.floor(Date.now() / 1000) - 10 * 60,
      },
      request.state,
    );
    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('rejected');
    expect(res.json().reason).toBe('kb_iat_fora_da_janela');
  });
});

// ---------------------------------------------------------------------------
// (e do enunciado) disclosure adulterada — digest não confere
// ---------------------------------------------------------------------------

describe('apresentação: integridade das disclosures', () => {
  it('vp_token com disclosure adulterada (valor trocado) → rejected', async () => {
    const { request } = await createSession(['nome', 'cargo']);
    const vpToken = await holderSdJwt.present(
      credential,
      { nome: true, cargo: true },
      {
        kb: {
          payload: {
            aud: request.client_id,
            nonce: request.nonce,
            iat: Math.floor(Date.now() / 1000),
          },
        },
      },
    );

    // vp_token = jwt~d1~...~dn~kbjwt — adultera a disclosure de "cargo",
    // mantendo salt e nome da claim, trocando apenas o valor.
    const parts = vpToken.split('~');
    const tamperedParts = parts.map((segment, i) => {
      if (i === 0 || i === parts.length - 1) return segment; // jwt e kb-jwt
      const decoded = JSON.parse(
        Buffer.from(segment, 'base64url').toString('utf8'),
      ) as [string, string, unknown];
      if (decoded[1] !== 'cargo') return segment;
      decoded[2] = 'Secretário Executivo'; // escalada de cargo adulterada
      return Buffer.from(JSON.stringify(decoded)).toString('base64url');
    });
    const tampered = tamperedParts.join('~');
    expect(tampered).not.toBe(vpToken);

    const res = await directPost(tampered, request.state);
    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('rejected');
    // digest da disclosure não confere com _sd (e o sd_hash do KB-JWT também não)
    expect(res.json().reason).toContain('apresentacao_invalida');
  });
});

// ---------------------------------------------------------------------------
// (g) assinatura do issuer validada — SD-JWT de issuer falso
// ---------------------------------------------------------------------------

describe('apresentação: assinatura do issuer (checklist g)', () => {
  it('SD-JWT assinado por issuer falso (outra chave ES256) → rejected', async () => {
    // Gera outro par ES256 e emite uma credencial com payload idêntico ao
    // legítimo — só a chave de assinatura muda.
    const fake = await jose.generateKeyPair('ES256', { extractable: true });
    const fakePrivateJwk = await jose.exportJWK(fake.privateKey);
    const fakeIssuer = new SDJwtVcInstance({
      signer: await ES256.getSigner(fakePrivateJwk),
      signAlg: 'ES256',
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
    });
    const fakeCredential = await fakeIssuer.issue(
      {
        vct: VCT_FUNCIONAL,
        iss: config.baseUrl,
        iat: Math.floor(Date.now() / 1000),
        cnf: { jwk: holderPublicJwk },
        status: {
          status_list: { idx: 0, uri: `${config.baseUrl}/status/token-status-list` },
        },
        nome: TEST_SERVIDOR.nome,
        cargo: TEST_SERVIDOR.cargo,
      },
      { _sd: ['nome', 'cargo'] },
    );

    const { request } = await createSession(['nome']);
    const res = await presentAndPost(
      fakeCredential,
      { nome: true },
      { aud: request.client_id, nonce: request.nonce },
      request.state,
    );
    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe('rejected');
    expect(res.json().reason).toContain('apresentacao_invalida');
  });
});

// ---------------------------------------------------------------------------
// Extras FINDINGS A-01 / A-02 — mock gov.br
// ---------------------------------------------------------------------------

describe('gov.br mock: allowlist de redirect_uri e XSS (extras do checklist)', () => {
  it('redirect_uri fora da allowlist no /govbr/authorize → 400', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/govbr/authorize',
      query: {
        client_id: 'luure-wallet-sou20-gov-sp',
        redirect_uri: 'https://atacante.example/callback',
        code_challenge: 'abc',
        code_challenge_method: 'S256',
        scope: 'openid',
        cpf: TEST_SERVIDOR.cpf,
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
  });

  it('XSS refletido: state com <script> na página de login (sem cpf) não sai cru no HTML', async () => {
    const payload = '<script>alert("xss")</script>';
    const res = await app.inject({
      method: 'GET',
      url: '/govbr/authorize',
      query: {
        client_id: 'luure-wallet-sou20-gov-sp',
        redirect_uri: 'http://localhost:8081/govbr/callback',
        code_challenge: 'abc',
        code_challenge_method: 'S256',
        scope: 'openid',
        state: payload,
        // sem cpf → devolve a página HTML de login que reflete o state
      },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    // o payload cru não pode aparecer; deve estar escapado como &lt;script&gt;
    expect(res.body).not.toContain('<script>alert');
    expect(res.body).toContain('&lt;script&gt;');
  });
});
