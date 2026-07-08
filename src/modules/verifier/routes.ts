import { createHash } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { nanoid } from 'nanoid';
import QRCode from 'qrcode';
import { prisma } from '../../lib/db.js';
import { config } from '../../lib/config.js';
import {
  CLAIMS_BY_VCT,
  SUPPORTED_VCTS,
  createVerifierInstance,
} from '../../lib/sdjwt.js';

const KB_IAT_WINDOW_SECONDS = 5 * 60;

const STATUS_LIST_URI = () => `${config.baseUrl}/status/token-status-list`;

class RejectionError extends Error {}

interface StatusClaim {
  status_list?: { idx?: number; uri?: string };
}

async function validatePresentation(
  vpToken: string,
  session: { vct: string; nonce: string; requestedClaims: string },
): Promise<Record<string, unknown>> {
  const instance = await createVerifierInstance();

  // Assinatura do issuer, presença e validade do KB-JWT (assinatura via
  // cnf.jwk, nonce da sessão, sd_hash) — a lib cobre tudo isso.
  // Status é validado manualmente abaixo consultando o banco (mesma fonte
  // do endpoint /status/token-status-list).
  let payload: Record<string, unknown>;
  let kbPayload: { iat: number; aud: string; nonce: string };
  try {
    const result = await instance.verify(vpToken, {
      keyBindingNonce: session.nonce,
      disableStatusVerification: true,
    });
    payload = result.payload as Record<string, unknown>;
    if (!result.kb) throw new Error('KB-JWT ausente');
    kbPayload = result.kb.payload;
  } catch (err) {
    throw new RejectionError(
      `apresentacao_invalida: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (payload.vct !== session.vct) {
    throw new RejectionError('vct_inesperado');
  }
  if (kbPayload.aud !== config.baseUrl) {
    throw new RejectionError('kb_aud_invalido');
  }
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - kbPayload.iat) > KB_IAT_WINDOW_SECONDS) {
    throw new RejectionError('kb_iat_fora_da_janela');
  }

  // Revogação: extrai idx/uri do claim status e confere no banco
  const status = payload.status as StatusClaim | undefined;
  const idx = status?.status_list?.idx;
  const uri = status?.status_list?.uri;
  if (typeof idx !== 'number' || uri !== STATUS_LIST_URI()) {
    throw new RejectionError('status_claim_invalido');
  }
  const issued = await prisma.credentialIssued.findUnique({
    where: { statusListIndex: idx },
  });
  if (!issued) {
    throw new RejectionError('credencial_desconhecida');
  }
  const jwtPart = vpToken.split('~')[0] ?? vpToken;
  const jwtHash = createHash('sha256').update(jwtPart).digest('hex');
  if (issued.sdJwtHash !== jwtHash || issued.vct !== payload.vct) {
    throw new RejectionError('credencial_inconsistente');
  }
  if (issued.revoked) {
    throw new RejectionError('credencial_revogada');
  }

  // Claims efetivamente divulgadas pela wallet (disclosures presentes).
  // Minimização imposta também no servidor (FINDINGS A-13): disclosures
  // excedentes às solicitadas na sessão são descartadas do resultado.
  const requested = new Set(JSON.parse(session.requestedClaims) as string[]);
  const decoded = await instance.decode(vpToken);
  const disclosed: Record<string, unknown> = {};
  for (const disclosure of decoded.disclosures ?? []) {
    if (disclosure.key && requested.has(disclosure.key)) {
      disclosed[disclosure.key] = disclosure.value;
    }
  }
  return disclosed;
}

export async function verifierRoutes(app: FastifyInstance): Promise<void> {
  const { baseUrl } = config;

  app.post<{ Body: { vct?: string; requested_claims?: string[] } }>(
    '/verifier/sessions',
    async (request, reply) => {
      const { vct, requested_claims: requestedClaims } = request.body ?? {};
      if (!vct || !SUPPORTED_VCTS.includes(vct as (typeof SUPPORTED_VCTS)[number])) {
        return reply.code(400).send({
          error: 'invalid_request',
          error_description: 'vct ausente ou não suportado',
        });
      }
      if (!Array.isArray(requestedClaims) || requestedClaims.length === 0) {
        return reply.code(400).send({
          error: 'invalid_request',
          error_description: 'requested_claims deve ser um array não vazio',
        });
      }
      const known = CLAIMS_BY_VCT[vct] ?? [];
      const unknown = requestedClaims.filter((c) => !known.includes(c));
      if (unknown.length > 0) {
        return reply.code(400).send({
          error: 'invalid_request',
          error_description: `claims desconhecidas para ${vct}: ${unknown.join(', ')}`,
        });
      }

      const session = await prisma.verificationSession.create({
        data: {
          nonce: nanoid(),
          state: nanoid(),
          vct,
          requestedClaims: JSON.stringify(requestedClaims),
          status: 'pending',
        },
      });

      const requestUri = `${baseUrl}/verifier/request/${session.id}`;
      const requestDeeplink = `openid4vp://?request_uri=${encodeURIComponent(requestUri)}`;
      const qrcodePngBase64 = await QRCode.toDataURL(requestDeeplink);

      return {
        id: session.id,
        request_uri: requestUri,
        request_deeplink: requestDeeplink,
        qrcode_png_base64: qrcodePngBase64,
      };
    },
  );

  app.get<{ Params: { id: string } }>(
    '/verifier/request/:id',
    async (request, reply) => {
      const session = await prisma.verificationSession.findUnique({
        where: { id: request.params.id },
      });
      if (!session) {
        return reply.code(404).send({ error: 'session_not_found' });
      }
      const requestedClaims = JSON.parse(session.requestedClaims) as string[];
      return {
        client_id: baseUrl,
        response_uri: `${baseUrl}/verifier/direct_post`,
        response_type: 'vp_token',
        response_mode: 'direct_post',
        nonce: session.nonce,
        state: session.state,
        dcql_query: {
          credentials: [
            {
              id: 'cred1',
              format: 'dc+sd-jwt',
              meta: { vct_values: [session.vct] },
              claims: requestedClaims.map((c) => ({ path: [c] })),
            },
          ],
        },
      };
    },
  );

  app.post<{ Body: { vp_token?: string; state?: string } }>(
    '/verifier/direct_post',
    async (request, reply) => {
      const { vp_token: vpToken, state } = request.body ?? {};
      if (!vpToken || !state) {
        return reply.code(400).send({
          error: 'invalid_request',
          error_description: 'vp_token e state são obrigatórios',
        });
      }
      const session = await prisma.verificationSession.findUnique({
        where: { state },
      });
      if (!session) {
        return reply.code(404).send({ error: 'session_not_found' });
      }
      // Nonce de sessão é single-use: só aceita apresentações em "pending"
      if (session.status !== 'pending') {
        return reply.code(400).send({ error: 'session_already_used' });
      }

      try {
        const disclosed = await validatePresentation(vpToken, session);
        await prisma.verificationSession.update({
          where: { id: session.id },
          data: { status: 'verified', resultClaims: JSON.stringify(disclosed) },
        });
        return { status: 'verified' };
      } catch (err) {
        const reason =
          err instanceof RejectionError ? err.message : 'erro_interno';
        await prisma.verificationSession.update({
          where: { id: session.id },
          data: { status: 'rejected', reason },
        });
        return { status: 'rejected', reason };
      }
    },
  );

  app.get<{ Params: { id: string } }>(
    '/verifier/sessions/:id',
    async (request, reply) => {
      const session = await prisma.verificationSession.findUnique({
        where: { id: request.params.id },
      });
      if (!session) {
        return reply.code(404).send({ error: 'session_not_found' });
      }
      return {
        status: session.status,
        ...(session.resultClaims
          ? { claims: JSON.parse(session.resultClaims) as Record<string, unknown> }
          : {}),
        ...(session.reason ? { reason: session.reason } : {}),
      };
    },
  );
}
