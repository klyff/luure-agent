# Checklist Criptográfico — Gate 2 / QA (Onda 2 → validado na Onda 3)

Verificação sobre o CÓDIGO FINAL. **Revalidação linha a linha em 2026-07-06
(Onda 3, review final)**: Issuer (`src/modules/issuer/routes.ts`), Verifier
(`src/modules/verifier/routes.ts`), Status List (`src/modules/status/routes.ts`),
lib SD-JWT server (`src/lib/sdjwt.ts`) e wallet core
(`sovereignid-wallet/src/core/*`) já existem e foram lidos. Cada item traz agora
status ✅/⚠️/❌ com evidência `arquivo:linha`.

Convenção de status:
- ✅ **COBERTO** — implementado corretamente, com evidência.
- ⚠️ **PARCIAL** — parte correta; resta lacuna apontada (ver FINDINGS Onda 3).
- ❌ **NÃO COBERTO** — critério exigido não implementado.

Resumo dos 8 itens (Onda 3): (a) ⚠️ · (b) ✅ · (c) ⚠️ · (d) ✅ · (e) ✅ ·
(f) ✅ · (g) ⚠️ · (h) ✅. Nenhum bloqueador de gate; 3 ressalvas médias
(A-12 c_nonce reutilizável, A-13 minimização não imposta no verifier,
A-14 wallet não valida assinatura do issuer).

## (a) Proof JWT de emissão (OID4VCI) — `POST /issuer/credential`

⚠️ **PARCIAL** — amarração chave↔credencial e single-use do pre-auth code
corretos; `c_nonce` reutilizável e sem janela de `iat`/checagem de `typ` (A-12).

- ✅ `aud` estrito == `credential_issuer`: `jose.jwtVerify(proof.jwt, holderKey, { audience: config.baseUrl })` — `src/modules/issuer/routes.ts:307-309`. Sem `startsWith`.
- ✅ `nonce` do proof == `c_nonce` do access_token: `payload.nonce !== tokenData.cNonce` rejeita — `routes.ts:310-311`; `c_nonce` amarrado ao token em `routes.ts:257-262`.
- ❌ **`c_nonce` NÃO é single-use** — após emissão bem-sucedida o access_token e o `cNonce` permanecem válidos por todo o TTL (600 s) e não são rotacionados (`routes.ts:280-363` nunca invalida). Reenviar o mesmo proof emite **outra** credencial → viola o critério. Ver **A-12**.
- ✅ Assinatura verificada com `header.jwk` e a MESMA JWK entra em `cnf.jwk`: `holderJwk = header.jwk` (`routes.ts:303-305`), verifica com ela (`:306-307`) e emite `cnf: { jwk: holderJwk }` (`:342`). Amarração correta — atacante com token roubado só recebe credencial ligada à chave DELE (inutilizável em apresentação sem a privada do holder).
- ⚠️ `typ` do header **não é verificado** e não há allowlist explícita de `alg` (`algorithms: ['ES256']`). `jose` rejeita `alg:none` por padrão e a importação da JWK EC quebra com `HS256`, mas falta o hardening explícito. Ver **A-12**.
- ❌ `iat` do proof **não é validado** (sem janela de frescor) — `routes.ts:307-309` não passa `maxTokenAge`. Combinado ao `c_nonce` reutilizável, amplia a janela de replay. Ver **A-12**.
- ✅ `pre-authorized_code` single-use: `status` transiciona `pending → claimed` (`routes.ts:236, 251-254`), segunda troca → `invalid_grant` (`:236`); `expiresAt` respeitado (`:239-245`).

## (b) KB-JWT (OID4VP) — `POST /verifier/direct_post`

✅ **COBERTO** — verificação de posse (KB-JWT) sólida; item mais forte da revisão.

- ✅ `aud` == `client_id`: `kbPayload.aud !== config.baseUrl` rejeita (`src/modules/verifier/routes.ts:52-54`); o `client_id` publicado no request é `baseUrl` (`:153`).
- ✅ `nonce` == `nonce` da sessão e **single-use**: a lib checa `nonce` (`node_modules/@sd-jwt/core/dist/index.js:756`) via `keyBindingNonce: session.nonce` (`routes.ts:37`); single-use garantido pela transição de status — só aceita `pending` (`routes.ts:190-192`) e grava `verified`/`rejected` em ambos os ramos (`:196-207`). Lookup por `state @unique` (`:183-184`). Obs.: `findUnique`+`update` fora de transação tem TOCTOU teórico (processo único da PoC → aceitável).
- ✅ `iat` dentro de janela e rejeita futuro: `Math.abs(now - iat) > KB_IAT_WINDOW_SECONDS` (`routes.ts:55-58`), `KB_IAT_WINDOW_SECONDS = 5*60` (`:13`). Janela de 5 min (recomendação era ≤2 min — aceitável, apenas mais folgada).
- ✅ `sd_hash` conferido pela lib: recalcula e compara, lançando em divergência (`@sd-jwt/core/dist/index.js:1310-1317`). `disableStatusVerification:true` NÃO desliga a checagem de KB (esta roda por `keyBindingNonce`).
- ✅ Assinatura do KB verificada contra `cnf.jwk` **DA CREDENCIAL** (não da requisição): `kbVerifier` usa `payload.cnf.jwk` do próprio SD-JWT (`src/lib/sdjwt.ts:65-68`).
- ✅ `typ` == `kb+jwt`: imposto pela lib (`@sd-jwt/core/dist/index.js:752`).

## (c) Minimização de disclosures

⚠️ **PARCIAL** — wallet envia só o selecionado; verifier NÃO filtra o excedente (A-13).

- ✅ Wallet envia SOMENTE as disclosures selecionadas: `selectDisclosures(parsed, selectedClaims)` filtra pelo nome da claim (`sovereignid-wallet/src/core/sdjwt.ts:115-118, 140`); `present.tsx` só marca as `requestedClaims` por padrão e envia `[...selected]` após consentimento (`src/app/present.tsx:79, 149`).
- ❌ **Verifier não impõe a minimização**: `validatePresentation` devolve TODAS as disclosures presentes no `vp_token` sem filtrar contra `session.requestedClaims` (`src/modules/verifier/routes.ts:82-88`) e grava tudo em `resultClaims` (`:198`). Uma wallet que enviar disclosure extra a repassa integralmente ao portal. Ver **A-13**.
- ⚠️ Teste negativo ausente: o e2e verifica que claims não divulgadas não aparecem (`src/__tests__/oid4vc.test.ts:266-269`), mas isso decorre de a wallet honesta enviar só o selecionado — não testa o descarte no verifier de disclosure não solicitada.

## (d) Status list consultada na verificação

✅ **COBERTO** — revogação verificada (via banco, documentado); status list assinada.

- ✅ `direct_post` resolve o claim `status` e checa o bit antes de `verified`: extrai `idx`/`uri` (`src/modules/verifier/routes.ts:60-66`), busca `credentialIssued` por `statusListIndex` (`:67-69`) e rejeita se `revoked` (`:78-79`).
- ✅ Revogação → `rejected` com `reason`: `credencial_revogada` (`routes.ts:79`); teste e2e confirma (`src/__tests__/oid4vc.test.ts:339-342`).
- ✅ Status list JWT assinada pelo issuer (ES256) com `iss`/`sub`/`iat` e `typ:statuslist+jwt` (`src/modules/status/routes.ts:36-43`). O verifier consulta o banco diretamente (`routes.ts:67-69`) em vez de validar o JWT — **aceitável na PoC (mesmo processo) e documentado no código** (`routes.ts:30-32`).
- ✅ `statusListIndex` único por credencial (`@unique` em schema). Obs.: `nextStatusListIndex` via `aggregate max` (`issuer/routes.ts:76-81`) tem corrida sob concorrência (PoC sequencial → aceitável).

## (e) PKCE S256 verificado no mock gov.br

✅ **COBERTO** (servidor):
- Método imposto: só `S256` é aceito — `src/modules/govbr-mock/routes.ts:132-137`.
- Verificação real do verifier: `s256(code_verifier) !== entry.codeChallenge` rejeita com `invalid_grant` — `src/modules/govbr-mock/routes.ts:210-215` (hash em `routes.ts:27-29`).
- Code single-use: `authCodes.delete(code)` após troca — `src/modules/govbr-mock/routes.ts:216`; TTL 5 min — `routes.ts:24,203`.
- Teste automatizado do caminho feliz e do verifier errado: `src/__tests__/app.test.ts:71-144` e `:146-178`.

✅ **COBERTO** (lado wallet, código final):
- ✅ `code_verifier` com CSPRNG: `randomBase64Url(32)` usa `Crypto.getRandomValues` do `expo-crypto` (`sovereignid-wallet/src/app/login.tsx:24-25, 40`); 32 bytes → 43 chars base64url. Não é logado (nenhum `console.log` em `login.tsx`).
- ✅ `state` validado no callback: `callbackParams["state"] !== state` lança erro (`login.tsx:66-68`); `state` também gerado com CSPRNG (`:42`).
- ✅ Servidor agora valida `redirect_uri` contra allowlist e re-confere no token (A-01 corrigido, ver §Extras).

## (f) `state` / `nonce` imprevisíveis

✅ **COBERTO** (o que existe):
- Authorization code do gov.br: `nanoid(32)` (CSPRNG, ~190 bits) — `src/modules/govbr-mock/routes.ts:164`.
- Access token do gov.br: `randomUUID()` (CSPRNG, 122 bits) — `src/modules/govbr-mock/routes.ts:228`.

✅ **COBERTO** (código final):
- ✅ Issuer: `pre-authorized_code` e `c_nonce` com `nanoid` (`src/modules/issuer/routes.ts:162, 257`); `tx_code` com `customAlphabet` numérico CSPRNG (`:25, 163`); access_token com `randomBytes(32)` (`:256`).
- ✅ Verifier: `nonce`/`state` com `nanoid` (`src/modules/verifier/routes.ts:121-122`).
- ✅ Wallet: `code_verifier`/`state` via `expo-crypto` (`login.tsx:24-25`); chave do holder via `expo-crypto` CSPRNG (`src/services/secure-key-store.ts:21-24`). **Nenhum `Math.random()` em fluxo de segurança nos dois repos** (grep confirmado).
- ✅ `state @unique` no schema; lookup do `direct_post` por `state` (`verifier/routes.ts:183-184`).

## (g) Assinatura do issuer validada via JWKS (sem confiança implícita)

⚠️ **PARCIAL** — verifier valida a assinatura do issuer; **a wallet NÃO valida ao receber** (A-14).

- ✅ Verifier valida a assinatura do issuer de fato: `createVerifierInstance` injeta `verifier: getIssuerVerifier()` (chave pública ES256) e `instance.verify` roda a verificação (`src/lib/sdjwt.ts:46-51, 72-80`; `verifier/routes.ts:36-39`). Não desserializa payload sem verificar. Usa a chave pública local (mesmo processo) em vez de resolver por `kid` no JWKS — aceitável na PoC.
- ❌ **Wallet confia cegamente na credencial recebida**: `receiveCredential` só faz `parseSdJwt` (`sovereignid-wallet/src/core/oid4vci.ts:174`), que decodifica e confere digests das disclosures (`src/core/sdjwt.ts:66-82`) mas **não verifica a assinatura do issuer** nem confere `iss` == `credential_issuer` antes de armazenar. `verifyJwtSignature` existe (`src/core/crypto.ts:144`) e é testada, porém **nunca é chamada no fluxo do app** (só em `scripts/core-tests.ts`). Ver **A-14**.
- ⚠️ Teste negativo (SD-JWT com outra chave → rejeitado): existe para o KB/portal no verifier; do lado wallet, `verifyJwtSignature` é testada isoladamente (`scripts/core-tests.ts:132-163`), mas não protege o recebimento real.
- ✅/⚠️ `alg`: o verifier server só aceita ES256 (assinatura ECDSA P-256 falha para `none`/`HS256`); a wallet, por não verificar no recebimento, não impõe `alg` algum nesse ponto (A-14).

## (h) Nenhuma PII em logs

✅ **COBERTO**:
- ✅ Servidor: logger desativado (`Fastify({ logger: false })` — `src/app.ts:11`); nenhum `console.log` com PII nos módulos.
- ✅ Wallet: os `console.log` de `scan.tsx:22` (conteúdo do QR) e `present.tsx:45` (claims) **foram REMOVIDOS** — grep confirma que não há mais `console.*` em `scan.tsx`/`present.tsx`/`login.tsx`. Restam apenas `console.warn` de falha de persistência em `wallet-store.ts` e `activity-store.ts` (logam o objeto de erro, não PII/segredo) — aceitável.
- ✅ Scripts de teste/e2e usam `console.log` apenas para nomes de teste e contadores (`scripts/core-tests.ts`, `scripts/e2e-flow.ts`) — sem PII.
- ⚠️ Nota para produção: se o logger do Fastify for ligado, configurar redaction de `authorization`, do body de `direct_post` e da query de `/govbr/authorize` (contém CPF na URL).

## Extras recomendados para o gate (fora da lista original)

- ✅ `redirect_uri` do `/govbr/authorize` validado contra `config.walletRedirectUris` (A-01 corrigido — `src/modules/govbr-mock/routes.ts:157-163`).
- ✅ `redirect_uri` re-conferido no `/govbr/token` contra o do authorize (A-01 — `routes.ts:243-249`).
- ✅ Escape do NOME e do VALOR do parâmetro + allowlist de params na página de login do mock (A-02 corrigido — `routes.ts:31-57`, `escapeHtml` + `FORWARDED_AUTHORIZE_PARAMS`).
- ✅ `client_id` conferido no `/govbr/token` quando enviado (A-03 corrigido — `routes.ts:209-215`).
- ✅ Biometria (`expo-local-authentication`) exigida antes de assinar o KB-JWT na apresentação (`sovereignid-wallet/src/app/present.tsx:116-142`); em aparelho sem biometria, segue com aviso explícito (aceitável na PoC).
- ⚠️ Novo (A-15): portal usa `innerHTML` com dados vindos da apresentação/seed (`web/index.html:219-223, 240-248`) — não explorável hoje (dados são assinados pelo issuer/seed), mas trocar por `textContent` é defesa em profundidade barata.
