import 'dotenv/config';
import { buildApp } from './app.js';
import { config } from './lib/config.js';

const app = await buildApp();

try {
  await app.listen({ port: config.port, host: '0.0.0.0' });
  console.log(`luure-agent-server ouvindo em ${config.baseUrl}`);
} catch (err) {
  console.error(err);
  process.exit(1);
}
