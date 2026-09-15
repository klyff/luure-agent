import { createHash } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import * as jose from 'jose';
import { buildApp } from '../app.js';
import { prisma } from '../lib/db.js';
import { getGovbrKeys } from '../lib/keys.js';
import { config } from '../lib/config.js';

const TEST_SERVIDOR = {
  cpf: '12345678901',
  nome: 'Ana Paula Ferreira',
  matricula: 'SEFAZ-118234',
  cargo: 'Agente Fiscal de Rendas',
  orgao: 'SEFAZ-SP',
  secretaria: 'Secretaria da Fazenda e Planejamento',
  vinculoAtivo: true,
  dataAdmissao: new Date('2012-03-15T00:00:00.000Z'),
  fotoHash: 'abc123',
  margemDisponivelCentavos: 285000,
  nivelContaGovbr: 'ouro',
};

let app: FastifyInstance;

beforeAll(async () => {
  await prisma.servidor.upsert({
    where: { cpf: TEST_SERVIDOR.cpf },
    update: TEST_SERVIDOR,
    create: TEST_SERVIDOR,
  });
  app = await buildApp();
});

afterAll(async () => {
  await app.close();
  await prisma.$disconnect();
});

describe('health', () => {
  it('GET /health responde ok', async () => {
    const res = await app.inject({ method: 'GET', url: '/health' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });
});

describe('sou-sp', () => {
  it('GET /sou-sp/servidores retorna seed com cpfMascarado', async () => {
    const res = await app.inject({ method: 'GET', url: '/sou-sp/servidores' });
    expect(res.statusCode).toBe(200);
    const list = res.json() as Array<{ cpf: string; cpfMascarado: string }>;
    const ana = list.find((s) => s.cpf === TEST_SERVIDOR.cpf);
    expect(ana).toBeDefined();
    expect(ana?.cpfMascarado).toBe('***.456.789-**');
  });
});

describe('fluxo gov.br mock (authorization code + PKCE)', () => {
  it('discovery expõe endpoints', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/govbr/.well-known/openid-configuration',
    });
    expect(res.statusCode).toBe(200);
    const meta = res.json() as Record<string, unknown>;
    expect(meta.issuer).toBe(config.govbrIssuer);
    expect(meta.code_challenge_methods_supported).toEqual(['S256']);
  });

  it('authorize -> token (PKCE) -> userinfo', async () => {
    const codeVerifier = 'verificador-pkce-de-teste-com-tamanho-suficiente-1234567890';
    const codeChallenge = createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');
    const redirectUri = 'http://localhost:8081/govbr/callback';

    // 1. authorize com cpf direto -> 302 com code
    const authRes = await app.inject({
      method: 'GET',
      url: '/govbr/authorize',
      query: {
        client_id: 'luure-wallet-sou20-gov-sp',
        redirect_uri: redirectUri,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: 'estado-teste',
        scope: 'openid',
        cpf: TEST_SERVIDOR.cpf,
      },
    });
    expect(authRes.statusCode).toBe(302);
    const location = new URL(authRes.headers.location as string);
    expect(location.origin + location.pathname).toBe(redirectUri);
    expect(location.searchParams.get('state')).toBe('estado-teste');
    const code = location.searchParams.get('code');
    expect(code).toBeTruthy();

    // 2. token com PKCE
    const tokenRes = await app.inject({
      method: 'POST',
      url: '/govbr/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code as string,
        code_verifier: codeVerifier,
        client_id: 'luure-wallet-sou20-gov-sp',
      }).toString(),
    });
    expect(tokenRes.statusCode).toBe(200);
    const tokens = tokenRes.json() as {
      access_token: string;
      id_token: string;
      token_type: string;
      expires_in: number;
    };
    expect(tokens.token_type).toBe('Bearer');
    expect(tokens.access_token).toBeTruthy();

    // id_token: assinatura ES256 verificável com a chave pública govbr
    const { publicKey } = getGovbrKeys();
    const { payload } = await jose.jwtVerify(tokens.id_token, publicKey, {
      issuer: config.govbrIssuer,
      audience: 'luure-wallet-sou20-gov-sp',
    });
    expect(payload.sub).toBe(TEST_SERVIDOR.cpf);
    expect(payload.name).toBe(TEST_SERVIDOR.nome);
    expect(payload.nivel_conta).toBe('ouro');
    expect(payload.amr).toEqual(['passwd']);

    // 3. userinfo com Bearer
    const userinfoRes = await app.inject({
      method: 'GET',
      url: '/govbr/userinfo',
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userinfoRes.statusCode).toBe(200);
    expect(userinfoRes.json()).toEqual({
      sub: TEST_SERVIDOR.cpf,
      name: TEST_SERVIDOR.nome,
      nivel_conta: 'ouro',
    });
  });

  it('token rejeita code_verifier errado', async () => {
    const codeVerifier = 'verificador-correto-abcdefghijklmnopqrstuvwxyz-0123456789';
    const codeChallenge = createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');

    const authRes = await app.inject({
      method: 'GET',
      url: '/govbr/authorize',
      query: {
        client_id: 'luure-wallet-sou20-gov-sp',
        redirect_uri: 'http://localhost:8081/govbr/callback',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        scope: 'openid',
        cpf: TEST_SERVIDOR.cpf,
      },
    });
    const code = new URL(authRes.headers.location as string).searchParams.get('code');

    const tokenRes = await app.inject({
      method: 'POST',
      url: '/govbr/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code as string,
        code_verifier: 'outro-verificador-que-nao-confere-9999999999999999999',
      }).toString(),
    });
    expect(tokenRes.statusCode).toBe(400);
    expect(tokenRes.json().error).toBe('invalid_grant');
  });

  it('authorize sem cpf retorna página HTML de login', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/govbr/authorize',
      query: {
        client_id: 'luure-wallet-sou20-gov-sp',
        redirect_uri: 'http://localhost:8081/govbr/callback',
        code_challenge: 'abc',
        code_challenge_method: 'S256',
        scope: 'openid',
      },
    });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.body).toContain('gov.br');
    expect(res.body).toContain('#1351B4');
  });
});
