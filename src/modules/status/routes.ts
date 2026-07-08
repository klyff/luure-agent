import { deflateSync } from 'node:zlib';
import type { FastifyInstance } from 'fastify';
import * as jose from 'jose';
import { prisma } from '../../lib/db.js';
import { config } from '../../lib/config.js';
import { getIssuerKeys } from '../../lib/keys.js';

/**
 * Token Status List (IETF draft, simplificado): bitstring com 1 bit por
 * credencial emitida (bit 1 = revogada), comprimido com zlib deflate e
 * codificado em base64url. O índice de cada credencial é o statusListIndex.
 */
async function buildStatusBitstring(): Promise<Buffer> {
  const issued = await prisma.credentialIssued.findMany({
    select: { statusListIndex: true, revoked: true },
  });
  const maxIndex = issued.reduce((m, c) => Math.max(m, c.statusListIndex), -1);
  const bytes = Buffer.alloc(Math.max(1, Math.ceil((maxIndex + 1) / 8)));
  for (const cred of issued) {
    if (cred.revoked) {
      bytes[Math.floor(cred.statusListIndex / 8)]! |=
        1 << cred.statusListIndex % 8;
    }
  }
  return bytes;
}

export async function statusRoutes(app: FastifyInstance): Promise<void> {
  const statusListUri = `${config.baseUrl}/status/token-status-list`;

  app.get('/status/token-status-list', async (_request, reply) => {
    const bitstring = await buildStatusBitstring();
    const lst = deflateSync(bitstring).toString('base64url');
    const { privateKey, kid } = getIssuerKeys();

    const jwt = await new jose.SignJWT({
      status_list: { bits: 1, lst },
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt', kid })
      .setIssuer(config.baseUrl)
      .setSubject(statusListUri)
      .setIssuedAt()
      .sign(privateKey);

    return reply.type('application/statuslist+jwt').send(jwt);
  });

  // ATENÇÃO (risco aceito na PoC): em produção este endpoint exigiria
  // autenticação/autorização de administrador — aqui é aberto para a demo.
  app.post<{ Body: { credential_id?: string } }>(
    '/admin/revoke',
    async (request, reply) => {
      const { credential_id: credentialId } = request.body ?? {};
      if (!credentialId) {
        return reply.code(400).send({
          error: 'invalid_request',
          error_description: 'credential_id é obrigatório',
        });
      }
      const issued = await prisma.credentialIssued.findUnique({
        where: { id: credentialId },
      });
      if (!issued) {
        return reply.code(404).send({ error: 'credential_not_found' });
      }
      await prisma.credentialIssued.update({
        where: { id: credentialId },
        data: { revoked: true },
      });
      return { revoked: true, credential_id: credentialId };
    },
  );
}
