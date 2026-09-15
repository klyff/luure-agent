# QA — PoC Luure (SOU.SP 2.0) — Onda 3

Documento de QA espelhado nos dois repositórios (`luure-agent-server` e
`luure-wallet-reactnative`). Consolida a matriz de testes, como rodar cada suíte, o
resultado da última execução e o checklist manual da demo.

Repositórios:
- **agent-server** — Fastify + Prisma (issuer/verifier OID4VC, mock gov.br, status list).
- **wallet** — React Native/Expo (SDK 57), core puro em `src/core`.

## 1. Matriz de testes

| Suíte | Onde | Comando | Tipo | Automatizado |
|---|---|---|---|---|
| Unitário do core | wallet `scripts/core-tests.ts` | `npm run test:core` | Unitário (Node puro) | ✅ |
| Vitest do server | agent-server `src/__tests__/*.test.ts` | `npm test` | Integração (fastify inject + test.db) | ✅ |
| E2E headless | wallet `scripts/e2e-flow.ts` | `npm run e2e` | E2E core ↔ servidor vivo | ✅ |
| Smoke negativo | wallet `scripts/smoke-negative.ts` | `npm run smoke:negative` | Casos negativos core ↔ servidor vivo | ✅ |
| Maestro smoke | wallet `e2e/*.yaml` | `maestro test e2e/` | UI (app no simulador) | ⚠️ Manual (ver §5) |

## 2. Como rodar cada suíte

### Servidor (agent-server)
```bash
# Vitest (usa test.db isolado; recria migrações a cada run). Não depende do
# servidor de dev estar de pé.
npm test
```

### Wallet
Pré-requisito para e2e e smoke: **servidor vivo** em `http://localhost:3100`
(sobrescreva com `E2E_BASE_URL`). Nenhum dos scripts sobe o servidor.

```bash
npm run test:core        # unitário do core, não precisa de servidor
npm run e2e              # E2E completo (emissão → apresentação → revogação)
npm run smoke:negative   # casos negativos do ponto de vista da wallet
```

### Maestro (UI)
Ver `e2e/README.md` na wallet. Requer CLI `maestro`, build de desenvolvimento e
o app instalado num simulador/emulador. **Não** foi executado no ambiente de QA
(binário `maestro` ausente); flows validados por revisão de sintaxe.

## 3. Resultado da execução final

Execução: **2026-07-06 ~22:08 (UTC-7)**, servidor de dev já de pé em `:3100`.

| Suíte | Comando | Resultado |
|---|---|---|
| Vitest server | `npm test` | **28 passaram / 0 falharam** (3 arquivos: app.test.ts, oid4vc.test.ts, security.test.ts) |
| Core wallet | `npm run test:core` | **11 passaram / 0 falharam** |
| E2E headless | `npm run e2e` | **6 passaram / 0 falharam** |
| Smoke negativo | `npm run smoke:negative` | **5 passaram / 0 falharam** |
| Maestro | `maestro test e2e/` | Não executado (CLI ausente) — 2 flows prontos/documentados |

Detalhe da suíte vitest do server (28):
- `app.test.ts` — 6 (health, sou-sp, fluxo gov.br PKCE feliz + verifier errado + login HTML).
- `oid4vc.test.ts` — 10 (metadata, emissão feliz, apresentação/privacidade, single-use, revogação).
- `security.test.ts` — **12 (novos nesta Onda 3)**.

## 4. Itens do CHECKLIST_ONDA2 cobertos por teste (mapa item → teste)

Arquivo dos testes novos: `src/__tests__/security.test.ts`.

| Item do checklist | Critério | Teste (arquivo :: it) |
|---|---|---|
| (a) proof — chave ≠ header.jwk | assinatura amarrada à JWK declarada | security :: "proof assinado por chave diferente da declarada no header.jwk → invalid_proof" |
| (a) proof — aud estrito | `aud == credential_issuer` | security :: "proof com aud diferente do credential_issuer → invalid_proof" |
| (a) proof — rejeitar alg none | `alg == ES256`, sem `none` | security :: "proof com alg none (JWT sem assinatura) → invalid_proof" |
| (a) pre-authorized_code single-use | segunda troca → invalid_grant | security :: "pre-authorized_code é single-use..." |
| (a) c_nonce single-use / reuso token | reuso de access_token e c_nonce | security :: "DOCUMENTADO: o design atual PERMITE reuso do access_token..." + "c_nonce de token antigo não é aceito com access_token novo → invalid_proof" |
| (a) nonce errado (pré-existente) | nonce ≠ c_nonce → invalid_proof | oid4vc :: "proof com nonce errado retorna 400 invalid_proof" |
| (b) KB-JWT aud errado | `aud == client_id` do verifier | security :: "KB-JWT com aud errado → rejected" |
| (b) KB-JWT iat fora da janela | iat em janela curta | security :: "KB-JWT com iat 10 minutos no passado → rejected" |
| (b) KB-JWT nonce da sessão (pré-existente) | nonce single-use da sessão | oid4vc :: "nonce de sessão errado no KB-JWT → rejected" + "sessão é single-use..." |
| (b)/(c) sd_hash / disclosure adulterada | digest não confere | security :: "vp_token com disclosure adulterada (valor trocado) → rejected" |
| (c) minimização de disclosures (pré-existente) | verifier só repassa claims pedidas | oid4vc :: "apresenta só nome+cargo..."; wallet e2e passo (e) |
| (d) status list / revogação (pré-existente) | revogada → rejected + bit 1 | oid4vc :: "credencial revogada → rejected e bit 1 na status list"; wallet e2e passo (f) |
| (e/PKCE — pré-existente) | S256 imposto e verificado | app.test :: "authorize -> token (PKCE)..." + "token rejeita code_verifier errado" |
| (g) assinatura do issuer via JWKS | SD-JWT de issuer falso → rejected | security :: "SD-JWT assinado por issuer falso (outra chave ES256) → rejected" |
| Extra A-01 redirect_uri allowlist | redirect_uri fora da allowlist → 400 | security :: "redirect_uri fora da allowlist no /govbr/authorize → 400" |
| Extra A-02 XSS refletido | state com `<script>` escapado | security :: "XSS refletido: state com <script>..." |

### O que ficou como verificação MANUAL (não automatizado)
- **Item (a) c_nonce single-use como requisito ideal**: o código atual mantém o
  par access_token/c_nonce válido até o TTL (600s) e **não** invalida após a
  emissão. O teste documenta isso como risco aceito da PoC; tornar single-use é
  uma mudança de design fora do escopo da QA.
- **Item (h) PII em logs**: exige `grep` manual pelos dois repos por
  `console.log`/`request.log` com CPF/nome/claims/tokens (checklist §h). Não há
  logger do Fastify ligado (`logger: false`), mas a wallet ainda tinha
  `console.log` em `scan.tsx`/`present.tsx` — conferir no gate.
- **Lado wallet do PKCE/state**: CSPRNG do `code_verifier`, tamanho ≥ 43 e
  validação de `state` no callback — coberto em código (`login.tsx`), verificar
  visualmente no gate.
- **Biometria antes de assinar** (checklist extra) — verificação manual no app.
- **Maestro smoke** — requer simulador (ver §5).

## 5. Checklist MANUAL da demo (passo a passo, pt-BR)

Ambiente: macOS com simulador iOS, servidor da PoC e app em dev build.

### Passo 0 — Subir o servidor
```bash
cd luure-agent-server
npm run seed          # popula 5 servidores do seed SOU.SP
npm start             # sobe em http://localhost:3100
```
**Esperado:** log de início sem erros; `curl http://localhost:3100/health` →
`{"status":"ok"}`.

### Passo 1 — Abrir o portal do emissor/verificador
No navegador: `http://localhost:3100/portal`
**Esperado:** portal carrega com opções de emitir credencial (gera QR/deeplink)
e criar sessão de verificação.

### Passo 2 — Rodar o app e chegar no login
```bash
cd luure-wallet-reactnative
npx expo run:ios
```
**Esperado:** app abre no onboarding ("Luure"). Tocar em **Começar** leva
à tela **Entrar** com o botão "Entrar com gov.br".

### Passo 3 — Login gov.br (mock)
Na tela de login, manter/into o CPF de teste do seed com vínculo ativo
(ex.: `12345678901` — Ana Paula Ferreira) e tocar **Entrar com gov.br**.
No popup do mock gov.br, confirmar o CPF e tocar **Continuar**.
**Esperado:** retorno ao app via deeplink `sovereignid://govbr/callback`;
a home "Minhas credenciais" é exibida.

### Passo 4 — Emitir credencial via QR
No portal (`/portal`), gerar uma oferta da **Carteira Funcional** para o CPF
logado. Copiar o **deeplink** `openid-credential-offer://...`.
No app, ir em **Adicionar credencial** (tela de scan). No simulador iOS (sem
câmera), **colar o deeplink** no campo de entrada da tela de scan e confirmar.
> Atalho DEV: alternativamente, tocar em "Emitir carteira funcional (dev)" na
> home emite direto, sem QR.
**Esperado:** banner de sucesso e um card "Carteira Funcional Digital" na home.

### Passo 5 — Apresentar com divulgação seletiva
No portal, criar uma **sessão de verificação** para a vct funcional pedindo
apenas `nome` e `cargo`; gerar o QR/deeplink `openid4vp://...`.
No app, iniciar a apresentação (colar o deeplink no simulador), revisar as
claims solicitadas, **selecionar apenas nome e cargo** e confirmar.
**Esperado:** o portal mostra a sessão como **verified** exibindo somente
`nome` e `cargo` — nenhuma outra claim (cpf_mascarado, matrícula, etc.) aparece.

### Passo 6 — Revogar e mostrar rejeição
No portal (ou via `POST /admin/revoke` com o `credential_id`/`jti` da credencial),
**revogar** a credencial recém-emitida. Criar nova sessão de verificação e
repetir a apresentação com a mesma credencial.
**Esperado:** a apresentação é **rejected** com motivo `credencial_revogada`; o
bit correspondente na status list (`GET /status/token-status-list`) está em 1.

---
_Última atualização: 2026-07-06 (Onda 3, QA)._
