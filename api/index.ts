import type { IncomingMessage, ServerResponse } from 'node:http';
import { buildApp } from '../src/app.js';

// A instância Fastify é reutilizada entre invocações (warm start).
const appPromise = (async () => {
  const app = await buildApp();
  await app.ready();
  return app;
})();

export default async function handler(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const app = await appPromise;
  app.server.emit('request', req, res);
}
