import path from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import formbody from '@fastify/formbody';
import fastifyStatic from '@fastify/static';
import { initKeys } from './lib/keys.js';
import { govbrRoutes } from './modules/govbr-mock/routes.js';
import { souSpRoutes } from './modules/sou-sp/routes.js';
import { issuerRoutes } from './modules/issuer/routes.js';
import { verifierRoutes } from './modules/verifier/routes.js';
import { statusRoutes } from './modules/status/routes.js';

export async function buildApp(): Promise<FastifyInstance> {
  await initKeys();

  const app = Fastify({ logger: false });

  // CORS liberado — aceitável apenas para a PoC
  await app.register(cors, { origin: true });
  await app.register(formbody);

  // process.cwd() funciona tanto local (raiz do repo) quanto na Vercel
  // (/var/task, com web/ incluída via includeFiles).
  await app.register(fastifyStatic, {
    root: path.resolve(process.cwd(), 'web'),
    prefix: '/portal/',
  });
  app.get('/portal', async (_request, reply) => reply.redirect('/portal/'));

  app.get('/health', async () => ({ status: 'ok' }));

  await app.register(govbrRoutes);
  await app.register(souSpRoutes);
  await app.register(issuerRoutes);
  await app.register(verifierRoutes);
  await app.register(statusRoutes);

  return app;
}
