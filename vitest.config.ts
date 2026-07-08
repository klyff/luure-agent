import { defineConfig } from 'vitest/config';

// Testes usam o Prisma Postgres local (npx prisma dev --name sovereignid --detach).
const TEST_DATABASE_URL =
  'postgres://postgres:postgres@localhost:51214/template1?sslmode=disable';

export default defineConfig({
  test: {
    env: {
      DATABASE_URL: TEST_DATABASE_URL,
    },
    globalSetup: './vitest.global-setup.ts',
    // Banco compartilhado entre arquivos de teste — evita escrita concorrente
    fileParallelism: false,
  },
});
