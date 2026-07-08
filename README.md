# luure-agent

Luure **Issuer/Verifier** agent server for OID4VC. Issues and verifies **SD-JWT VC**
credentials via **OID4VCI** (issuance) and **OID4VP** (presentation), with a mock gov.br
IdP and status list for revocation.

## Stack

- Node 22+ / TypeScript / Fastify
- Prisma + PostgreSQL (production) — SQLite for local dev via `DATABASE_URL`
- `@sd-jwt/*` (OpenWallet Foundation) + `jose`

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `BASE_URL` | Yes (production) | Public URL of the deployed agent (e.g. `https://luure-agent.vercel.app`) |
| `DATABASE_URL` | Yes (production) | PostgreSQL connection string (e.g. `postgresql://user:pass@host:5432/luure`) |
| `ISSUER_ID` | Yes (production) | Issuer identifier used in credentials (typically same as `BASE_URL`) |
| `PORT` | No | HTTP port for local dev (default `3100`) |
| `GOVBR_ISSUER` | No | Mock gov.br issuer URL (default `{BASE_URL}/govbr`) |
| `ALLOW_EXPO_REDIRECT` | No | Set to `1` to allow Expo Go redirect URIs in production |

Copy `.env.example` for local development:

```bash
cp .env.example .env
```

## Local development

```bash
npm install
npx prisma migrate dev
npm run seed
npm run dev        # http://localhost:3100
```

Verifier demo portal: `http://localhost:3100/portal`.

## Deploy to Vercel

1. **Create a Vercel project** linked to this repository (`klyff/luure-agent`).

2. **Add a PostgreSQL database** (Vercel Postgres, Neon, Supabase, etc.) and note the connection string.

3. **Set environment variables** in the Vercel project settings:

   - `BASE_URL` — your deployment URL (e.g. `https://luure-agent.vercel.app`)
   - `DATABASE_URL` — PostgreSQL connection string
   - `ISSUER_ID` — same as `BASE_URL` unless you use a dedicated issuer DID/URL

4. **Deploy** — Vercel uses `vercel.json` to route all traffic through `api/index.ts` (serverless Fastify).

   ```bash
   npx vercel --prod
   ```

5. **Run migrations** against the production database after first deploy:

   ```bash
   DATABASE_URL="<production-url>" npx prisma migrate deploy
   DATABASE_URL="<production-url>" npm run seed
   ```

## CI

GitHub Actions runs on every push and pull request: `npm ci`, `npm run typecheck`, `npm test`.

## Contracts

See [CONTRACTS.md](CONTRACTS.md) for the wallet integration contract.
