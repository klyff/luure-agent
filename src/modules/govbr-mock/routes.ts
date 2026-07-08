import { createHash, randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import * as jose from 'jose';
import { nanoid } from 'nanoid';
import { config, isAllowedWalletRedirectUri } from '../../lib/config.js';
import { prisma } from '../../lib/db.js';
import {
  ephemeralDelete,
  ephemeralGet,
  ephemeralSet,
} from '../../lib/ephemeral.js';
import { getGovbrKeys } from '../../lib/keys.js';

interface AuthCodeEntry {
  cpf: string;
  codeChallenge: string;
  redirectUri: string;
}

interface AccessTokenEntry {
  cpf: string;
}

const AUTH_CODE_TTL_MS = 5 * 60 * 1000;
const ACCESS_TOKEN_TTL_S = 3600;

function s256(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Somente parâmetros OAuth conhecidos são re-emitidos no formulário (FINDINGS A-02).
const FORWARDED_AUTHORIZE_PARAMS = new Set([
  'client_id',
  'redirect_uri',
  'code_challenge',
  'code_challenge_method',
  'state',
  'scope',
]);

function loginPage(
  servidores: { cpf: string; nome: string }[],
  query: Record<string, string | undefined>,
  errorMessage?: string,
): string {
  const params = Object.entries(query)
    .filter(([k, v]) => v !== undefined && FORWARDED_AUTHORIZE_PARAMS.has(k))
    .map(
      ([k, v]) =>
        `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(String(v))}" />`,
    )
    .join('\n      ');
  const hints = servidores
    .map((s) => `<li><code>${escapeHtml(s.cpf)}</code> — ${escapeHtml(s.nome)}</li>`)
    .join('\n        ');
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>gov.br — Entrar (mock)</title>
  <style>
    body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; background: #f8f8f8; margin: 0; }
    header { background: #1351B4; color: #fff; padding: 16px 24px; font-weight: 700; font-size: 20px; }
    main { max-width: 420px; margin: 40px auto; background: #fff; border-radius: 8px; padding: 32px; box-shadow: 0 1px 6px rgba(0,0,0,.12); }
    h1 { font-size: 18px; color: #1351B4; margin-top: 0; }
    label { display: block; margin-bottom: 8px; font-size: 14px; }
    input[type=text] { width: 100%; padding: 10px; border: 1px solid #888; border-radius: 4px; box-sizing: border-box; }
    button { margin-top: 16px; width: 100%; background: #1351B4; color: #fff; border: none; border-radius: 24px; padding: 12px; font-size: 16px; font-weight: 600; cursor: pointer; }
    button:hover { background: #0c3d8a; }
    .hint { margin-top: 24px; font-size: 12px; color: #555; }
    .hint code { background: #eef; padding: 1px 4px; border-radius: 3px; }
    .erro { background: #fdeceb; border-left: 4px solid #E52207; color: #7d1408; padding: 10px 12px; border-radius: 4px; font-size: 14px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <header>gov.br <small style="font-weight:400">(mock PoC)</small></header>
  <main>
    <h1>Identifique-se no gov.br</h1>
    ${errorMessage ? `<div class="erro">${escapeHtml(errorMessage)}</div>` : ''}
    <form method="GET" action="/govbr/authorize">
      ${params}
      <label for="cpf">Número do CPF</label>
      <input type="text" id="cpf" name="cpf" placeholder="Digite seu CPF (somente números)" />
      <button type="submit">Continuar</button>
    </form>
    <div class="hint">
      <p>CPFs de teste (seed SOU.SP):</p>
      <ul>
        ${hints}
      </ul>
    </div>
  </main>
</body>
</html>`;
}

export async function govbrRoutes(app: FastifyInstance): Promise<void> {
  app.get('/govbr/.well-known/openid-configuration', async () => {
    const base = config.govbrIssuer;
    return {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      userinfo_endpoint: `${base}/userinfo`,
      jwks_uri: `${base}/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
      scopes_supported: ['openid'],
      claims_supported: ['sub', 'name', 'nivel_conta', 'amr'],
    };
  });

  app.get('/govbr/jwks.json', async () => {
    const { publicJwk } = getGovbrKeys();
    return { keys: [publicJwk] };
  });

  app.get<{
    Querystring: {
      client_id?: string;
      redirect_uri?: string;
      code_challenge?: string;
      code_challenge_method?: string;
      state?: string;
      scope?: string;
      cpf?: string;
    };
  }>('/govbr/authorize', async (request, reply) => {
    const {
      client_id,
      redirect_uri,
      code_challenge,
      code_challenge_method,
      state,
      cpf,
    } = request.query;

    if (client_id !== config.walletClientId) {
      return reply.code(400).send({
        error: 'invalid_client',
        error_description: `client_id inválido (esperado ${config.walletClientId})`,
      });
    }
    if (!code_challenge || (code_challenge_method ?? 'S256') !== 'S256') {
      return reply.code(400).send({
        error: 'invalid_request',
        error_description: 'code_challenge obrigatório com code_challenge_method=S256',
      });
    }
    // FINDINGS A-01: redirect_uri deve pertencer à allowlist registrada do client.
    if (!redirect_uri || !isAllowedWalletRedirectUri(redirect_uri)) {
      return reply.code(400).send({
        error: 'invalid_request',
        error_description: 'redirect_uri ausente ou não registrado para este client',
      });
    }

    if (!cpf) {
      const servidores = await prisma.servidor.findMany({
        select: { cpf: true, nome: true },
        orderBy: { nome: 'asc' },
      });
      return reply
        .code(200)
        .header('content-type', 'text/html; charset=utf-8')
        .send(loginPage(servidores, request.query as Record<string, string | undefined>));
    }

    const servidor = await prisma.servidor.findUnique({ where: { cpf } });
    if (!servidor) {
      // Reapresenta o formulário com erro amigável (em vez de JSON cru no
      // navegador do usuário) — o fluxo OAuth continua pendente até acertar.
      const servidores = await prisma.servidor.findMany({
        select: { cpf: true, nome: true },
        orderBy: { nome: 'asc' },
      });
      return reply
        .code(200)
        .header('content-type', 'text/html; charset=utf-8')
        .send(
          loginPage(
            servidores,
            request.query as Record<string, string | undefined>,
            `CPF ${cpf} não encontrado na base SOU.SP. Use um dos CPFs de teste abaixo.`,
          ),
        );
    }

    const code = nanoid(32);
    await ephemeralSet(
      `govbr:code:${code}`,
      { cpf, codeChallenge: code_challenge, redirectUri: redirect_uri } satisfies AuthCodeEntry,
      AUTH_CODE_TTL_MS,
    );

    const location = new URL(redirect_uri);
    location.searchParams.set('code', code);
    if (state) location.searchParams.set('state', state);
    return reply.code(302).header('location', location.toString()).send();
  });

  app.post<{
    Body: {
      grant_type?: string;
      code?: string;
      code_verifier?: string;
      redirect_uri?: string;
      client_id?: string;
    };
  }>('/govbr/token', async (request, reply) => {
    const { grant_type, code, code_verifier, redirect_uri, client_id } = request.body ?? {};

    // FINDINGS A-03: client_id, quando enviado, deve ser o registrado.
    if (client_id !== undefined && client_id !== config.walletClientId) {
      return reply.code(400).send({
        error: 'invalid_client',
        error_description: 'client_id não registrado',
      });
    }
    if (grant_type !== 'authorization_code') {
      return reply.code(400).send({
        error: 'unsupported_grant_type',
        error_description: 'grant_type deve ser authorization_code',
      });
    }
    if (!code || !code_verifier) {
      return reply.code(400).send({
        error: 'invalid_request',
        error_description: 'code e code_verifier são obrigatórios',
      });
    }

    const entry = await ephemeralGet<AuthCodeEntry>(`govbr:code:${code}`);
    if (!entry) {
      return reply.code(400).send({
        error: 'invalid_grant',
        error_description: 'authorization code inválido ou expirado',
      });
    }
    if (s256(code_verifier) !== entry.codeChallenge) {
      return reply.code(400).send({
        error: 'invalid_grant',
        error_description: 'code_verifier não confere com code_challenge (S256)',
      });
    }
    // FINDINGS A-01: redirect_uri do token, quando enviado, deve repetir o do authorize.
    if (redirect_uri !== undefined && redirect_uri !== entry.redirectUri) {
      return reply.code(400).send({
        error: 'invalid_grant',
        error_description: 'redirect_uri divergente do utilizado no authorize',
      });
    }
    await ephemeralDelete(`govbr:code:${code}`);

    const servidor = await prisma.servidor.findUnique({
      where: { cpf: entry.cpf },
    });
    if (!servidor) {
      return reply.code(400).send({
        error: 'invalid_grant',
        error_description: 'servidor não encontrado',
      });
    }

    const accessToken = `govbr_${randomUUID()}`;
    await ephemeralSet(
      `govbr:token:${accessToken}`,
      { cpf: servidor.cpf } satisfies AccessTokenEntry,
      ACCESS_TOKEN_TTL_S * 1000,
    );

    const { privateKey, kid } = getGovbrKeys();
    const idToken = await new jose.SignJWT({
      name: servidor.nome,
      nivel_conta: servidor.nivelContaGovbr,
      amr: ['passwd'],
    })
      .setProtectedHeader({ alg: 'ES256', kid, typ: 'JWT' })
      .setIssuer(config.govbrIssuer)
      .setSubject(servidor.cpf)
      .setAudience(config.walletClientId)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);

    return {
      access_token: accessToken,
      id_token: idToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_S,
    };
  });

  app.get('/govbr/userinfo', async (request, reply) => {
    const auth = request.headers.authorization;
    const token = auth?.startsWith('Bearer ') ? auth.slice(7) : undefined;
    const entry = token
      ? await ephemeralGet<AccessTokenEntry>(`govbr:token:${token}`)
      : undefined;

    if (!entry) {
      return reply.code(401).send({
        error: 'invalid_token',
        error_description: 'access_token ausente, inválido ou expirado',
      });
    }

    const servidor = await prisma.servidor.findUnique({
      where: { cpf: entry.cpf },
    });
    if (!servidor) {
      return reply.code(401).send({ error: 'invalid_token' });
    }

    return {
      sub: servidor.cpf,
      name: servidor.nome,
      nivel_conta: servidor.nivelContaGovbr,
    };
  });
}
