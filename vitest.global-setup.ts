import { execSync } from 'node:child_process';
import path from 'node:path';
import pg from 'pg';

const TEST_DATABASE_URL =
  'postgres://postgres:postgres@localhost:51214/template1?sslmode=disable';

export default async function setup(): Promise<void> {
  const root = path.resolve(import.meta.dirname);

  // Recria o schema para garantir estado limpo entre execuções.
  const client = new pg.Client({ connectionString: TEST_DATABASE_URL });
  await client.connect();
  await client.query('DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;');
  await client.end();

  execSync('npx prisma migrate deploy', {
    cwd: root,
    env: { ...process.env, DATABASE_URL: TEST_DATABASE_URL },
    stdio: 'inherit',
  });
}
