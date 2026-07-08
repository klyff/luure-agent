# Achados de Segurança — Revisão Onda 2 (código existente em 2026-07-06)

Escopo revisado: todo o `src/` de `sovereignid-agent-server` (módulos `govbr-mock`,
`sou-sp`, libs, testes, Prisma) e todo o `src/` de `sovereignid-wallet` (Onda 1: UI
com mocks, sem wallet core criptográfico ainda). Issuer OID4VCI, Verifier OID4VP e
Status List ainda não existem no código — cobertos por `CHECKLIST_ONDA2.md`.

## Destaque

**Nenhum achado CRÍTICO no código existente.** Não há verificação de assinatura
ausente nem segredo commitado: os fluxos criptográficos centrais (emissão e
apresentação) ainda não foram escritos, e o que existe (PKCE no mock gov.br,
assinatura do id_token) está correto. O achado mais relevante é A-01
(`redirect_uri` sem allowlist), de correção barata e recomendada ainda na Onda 2.

Resumo: 0 críticos · 1 alto · 3 médios · 4 baixos · 3 informativos.

> **Atualização Onda 3 (2026-07-06, review final do código completo)**: A-01,
> A-02, A-03 e A-05 foram **CORRIGIDOS** (evidências abaixo). O review final do
> Issuer/Verifier/Status/wallet-core acrescentou 3 achados médios e 1 baixo,
> registrados na seção **"Review final (Onda 3)"** ao fim deste documento.
> **Não há bloqueador de gate**: a autenticidade (assinatura do issuer no
> verifier), o binding de posse (KB-JWT contra `cnf.jwk` da credencial) e a
> revogação estão corretos.

---

## Alto

### A-01 — `redirect_uri` não validado contra allowlist no mock gov.br  ✅ CORRIGIDO (Onda 3)

> **Status Onda 3: CORRIGIDO.** O `/govbr/authorize` agora rejeita `redirect_uri`
> ausente ou fora da allowlist `config.walletRedirectUris`
> (`src/modules/govbr-mock/routes.ts:157-163`), e o `/govbr/token` re-confere o
> `redirect_uri` contra o guardado no code quando enviado (`routes.ts:243-249`).
> Achado original abaixo, mantido para rastreabilidade.


- **Evidência**: `src/modules/govbr-mock/routes.ts:138-143` — só exige presença:

  ```ts
  if (!redirect_uri) {
    return reply.code(400).send({ error: 'invalid_request', ... });
  }
  ```

  O authorization code é enviado por 302 para QUALQUER URI (`routes.ts:172-175`).
  A allowlist existe em `src/lib/config.ts:7-10` (`walletRedirectUris`) mas **nunca
  é usada** no código. Além disso, `entry.redirectUri` é armazenado com o code
  (`routes.ts:168`) porém o `POST /govbr/token` não recebe/compara `redirect_uri`
  (`routes.ts:186-216`), violando o RFC 6749 §4.1.3.
- **Impacto**: um link de authorize forjado exfiltra o code para servidor do
  atacante. O PKCE limita a troca por token a quem tem o `code_verifier`, mas se o
  atacante monta o link inteiro (challenge próprio), obtém id_token/access_token de
  qualquer CPF do seed. Na PoC o impacto prático é reduzido (o mock não autentica
  ninguém de verdade — RA-06), mas o padrão inseguro tende a ser copiado para
  código real.
- **Recomendação**: validar `redirect_uri` contra `config.walletRedirectUris` no
  `/govbr/authorize` e comparar o `redirect_uri` do `/govbr/token` com
  `entry.redirectUri`. ~6 linhas; fazer ainda na Onda 2.

## Médio

### A-02 — XSS refletido na página de login do mock gov.br (nome do parâmetro)  ✅ CORRIGIDO (Onda 3)

> **Status Onda 3: CORRIGIDO.** Agora tanto o NOME quanto o VALOR passam por
> `escapeHtml` (`&`, `<`, `>`, `"`, `'`) e só parâmetros de uma allowlist OAuth
> (`FORWARDED_AUTHORIZE_PARAMS`) são reemitidos no formulário
> (`src/modules/govbr-mock/routes.ts:31-57`). Achado original abaixo.

- **Evidência**: `src/modules/govbr-mock/routes.ts:32-38` — o VALOR do query param
  é escapado (`"` → `&quot;`), mas o NOME (`k`) é interpolado sem escape:

  ```ts
  `<input type="hidden" name="${k}" value="${String(v).replace(/"/g, '&quot;')}" />`
  ```

  Uma URL como `/govbr/authorize?client_id=...&x%22%20autofocus%20onfocus%3D%22alert(1)=1`
  injeta atributos/handlers no HTML refletido.
- **Impacto**: XSS na página onde a vítima digita CPF — exatamente o alvo de um
  phishing de login. Mock local, dados fictícios, mas é a superfície HTML exposta.
- **Recomendação**: escapar `k` (ou aceitar somente a lista fixa de parâmetros
  OIDC conhecidos: `client_id`, `redirect_uri`, `code_challenge`,
  `code_challenge_method`, `state`, `scope`).

### A-03 — `POST /govbr/token` não valida `client_id`  ✅ CORRIGIDO (Onda 3)

> **Status Onda 3: CORRIGIDO.** O `/govbr/token` agora rejeita `client_id`
> divergente de `config.walletClientId` quando enviado
> (`src/modules/govbr-mock/routes.ts:209-215`). Achado original abaixo.

- **Evidência**: `src/modules/govbr-mock/routes.ts:186-216` — o body declara
  `client_id` no tipo, mas o handler nunca o confere (o `/authorize` confere,
  `routes.ts:126-131`). Como é client público com PKCE, o RFC 6749 §3.2.1 exige o
  `client_id` na requisição de token para clients não autenticados.
- **Impacto**: baixo na PoC (client único); em produção permitiria mix-up entre
  clients.
- **Recomendação**: exigir `client_id === config.walletClientId` no token endpoint.

### A-04 — `/sou-sp/servidores` expõe CPF completo e margem sem autenticação

- **Evidência**: `src/modules/sou-sp/routes.ts:18-19`:

  ```ts
  // cpf completo exposto apenas para fins de demo da PoC
  cpf: s.cpf,
  ```

- **Impacto**: qualquer um na rede lê PII (fictícia) de todos os servidores do
  seed, incluindo margem consignável e vínculo. Já reconhecido no próprio código.
- **Recomendação**: manter como **risco aceito RA-07** (dados de seed), mas marcar
  o endpoint como demo-only no CONTRACTS e garantir que nunca receba dados reais.
  Se o portal demo só precisa de `cpfMascarado`, remover o campo `cpf` é gratuito.

## Baixo

### A-05 — Wallet loga conteúdo do QR e claims no console  ✅ CORRIGIDO (Onda 3)

> **Status Onda 3: CORRIGIDO.** Os `console.log` de `scan.tsx` e `present.tsx`
> foram removidos (grep confirma ausência de `console.*` nessas telas e em
> `login.tsx`). Restam apenas `console.warn` de erro de persistência em
> `wallet-store.ts`/`activity-store.ts`, sem PII. Achado original abaixo.

- **Evidência**: `sovereignid-wallet/src/app/scan.tsx:22`
  (`console.log("[scan] valor capturado:", value)`) e
  `sovereignid-wallet/src/app/present.tsx:45`
  (`console.log("[present] claims compartilhadas:", ...)`).
- **Impacto**: hoje só dados mock; na Onda 2 esses mesmos pontos manipularão
  deeplinks com `credential_offer_uri`/`pre-authorized_code` e claims reais —
  vazariam segredos efêmeros e PII para o console/Metro. Viola o item (h) do
  checklist.
- **Recomendação**: remover ou reduzir a metadados (ex.: logar só o scheme do
  deeplink) antes do build da Onda 2.

### A-06 — Maps em memória de codes/tokens sem expurgo de expirados

- **Evidência**: `src/modules/govbr-mock/routes.ts:21-22` (`authCodes`,
  `accessTokens`); TTL é checado na leitura (`routes.ts:203`, `:261`) mas entradas
  expiradas não usadas nunca são removidas.
- **Impacto**: crescimento de memória e retenção de CPF em RAM além do necessário.
  Irrelevante para uma demo curta.
- **Recomendação**: `setInterval` simples de limpeza ou aceitar na PoC.

### A-07 — `id_token` sem suporte a `nonce` OIDC

- **Evidência**: `/govbr/authorize` não aceita/propaga `nonce`
  (`routes.ts:106-124`) e o `id_token` não o inclui (`routes.ts:235-246`). O
  `CONTRACTS.md` §1 também não o prevê.
- **Impacto**: sem `nonce`, um id_token capturado pode ser reinjetado no client
  (replay). Mitigado parcialmente por `state` + PKCE + TLS ausente ser risco aceito.
- **Recomendação**: aceitar na PoC; anotar como divergência do OIDC Core para o
  gate (se a wallet enviar `nonce`, ecoar no id_token).

### A-08 — Arquivos de chave privada com permissão 0644 e chave extraível

- **Evidência**: `keys/issuer.jwk.json` e `keys/govbr.jwk.json` (mode `-rw-r--r--`,
  contêm o campo `d`); geração com `extractable: true` em `src/lib/keys.ts:21-23`;
  escrita sem `mode` restritivo em `keys.ts:29`.
- **Impacto**: qualquer usuário local lê as chaves. É o risco aceito RA-02.
- **Recomendação**: melhoria barata dentro da PoC: `writeFileSync(..., { mode: 0o600 })`.

## Informativo

### A-09 — CORS aberto (`origin: true`)

- **Evidência**: `src/app.ts:14`, com comentário explícito "aceitável apenas para a
  PoC". Risco aceito RA-08. OK.

### A-10 — Sem rate limiting e sem log de auditoria

- **Evidência**: `src/app.ts:11` (`logger: false`); nenhum plugin de rate limit
  registrado. Risco aceito RA-10. Atenção ao ligar o logger na Onda 2: a query de
  `/govbr/authorize` contém CPF na URL — configurar redaction.

### A-11 — `.env` presente mas ignorado pelo git

- **Evidência**: `.env` (39 bytes) na raiz do servidor; `.gitignore` cobre `.env`,
  `keys/`, `dev.db*`, `test.db*`. Verificado: nada sensível rastreável pelo git. OK.

---

## Aspectos positivos confirmados

| # | Aspecto | Evidência |
|---|---|---|
| P-01 | PKCE S256 implementado corretamente: método imposto, digest comparado, code single-use com TTL de 5 min | `src/modules/govbr-mock/routes.ts:27-29, 132-137, 203-216` |
| P-02 | Teste negativo de PKCE (verifier errado → `invalid_grant`) | `src/__tests__/app.test.ts:146-178` |
| P-03 | Aleatoriedade adequada: `nanoid(32)` para authorization code, `randomUUID()` para access token (ambos CSPRNG) | `routes.ts:164, 228` |
| P-04 | `id_token` ES256 com `kid`, `iss`, `sub`, `aud`, `iat`, `exp` corretos, e teste que VERIFICA a assinatura com `jose.jwtVerify` (não confiança implícita) | `routes.ts:234-246`; `app.test.ts:121-130` |
| P-05 | `client_id` validado no `/govbr/authorize` | `routes.ts:126-131` |
| P-06 | Segredos fora do git: `keys/`, `dev.db*`, `.env` no `.gitignore` | `.gitignore` do agent-server |
| P-07 | JWKS público derivado removendo `d` antes de expor (`/govbr/jwks.json` só publica a pública) | `src/lib/keys.ts:33-34`; `routes.ts:101-104` |
| P-08 | Modelo de dados já preparado para as garantias da Onda 2: `CredentialOffer.status` (single-use do pre-auth code), `VerificationSession.state @unique`, `CredentialIssued.statusListIndex @unique` | `prisma/schema.prisma:36, 49, 62` |
| P-09 | Helper de mascaramento de CPF centralizado e testado | `src/modules/sou-sp/routes.ts:4-7`; `app.test.ts:49-56` |
| P-10 | Stack SD-JWT baseada em bibliotecas mantidas (`@sd-jwt/core`, `@sd-jwt/sd-jwt-vc`, `jose`) em vez de cripto artesanal | `package.json` do agent-server |
| P-11 | UX da wallet já modela consentimento e divulgação seletiva por claim (checkbox por claim, nada enviado sem ação do usuário) | `sovereignid-wallet/src/app/present.tsx:29-40` |

---

# Review final (Onda 3) — código completo OID4VCI/OID4VP/SD-JWT

Revisão linha a linha do código FINAL (Issuer, Verifier, Status List, lib SD-JWT
do server e wallet core), realizada em 2026-07-06 após conclusão da implementação.

## Destaque da Onda 3

**Nenhum BLOQUEADOR DE GATE.** Os três pilares de autenticidade/binding/divulgação
estão corretos no caminho principal:
- **Autenticidade**: o verifier valida de fato a assinatura ES256 do issuer sobre
  o SD-JWT (`src/lib/sdjwt.ts:72-80` + `verifier/routes.ts:36-39`), sem
  desserializar payload sem verificar.
- **Binding de posse**: o KB-JWT é verificado contra a `cnf.jwk` **da própria
  credencial** (`src/lib/sdjwt.ts:65-68`), com `aud`, `nonce` de sessão single-use,
  `iat` e `sd_hash` conferidos.
- **Divulgação**: a wallet só envia as disclosures selecionadas
  (`wallet/src/core/sdjwt.ts:115-118`).

Achados novos: **0 críticos · 0 altos · 3 médios · 1 baixo**. Nenhum quebra
autenticidade, binding ou confidencialidade dentro do modelo de ameaça da PoC.

## Médio

### A-12 — `c_nonce` reutilizável e proof sem janela de `iat`/checagem de `typ` (issuer)

- **Severidade**: Média.
- **Evidência**: `src/modules/issuer/routes.ts:280-363`. Após emissão bem-sucedida,
  o access_token e o `cNonce` associado permanecem válidos por todo o TTL (600 s)
  e **não são invalidados nem rotacionados**. `jose.jwtVerify` do proof
  (`routes.ts:307-309`) não passa `maxTokenAge` (não valida `iat`) nem
  `algorithms: ['ES256']`, e o `typ` do header (`openid4vci-proof+jwt`) não é
  conferido.
- **Impacto**: um cliente com o access_token pode reenviar o MESMO proof e emitir
  **múltiplas credenciais** dentro da janela do token — viola o requisito de
  `c_nonce` single-use do checklist (a). Impacto de autenticidade é **baixo**: as
  credenciais duplicadas ficam todas amarradas à `cnf.jwk` do holder legítimo (o
  atacante não possui a chave privada para apresentá-las). `alg:none` já é
  rejeitado pelo `jose` por padrão e a importação de JWK EC quebra com `HS256`, mas
  falta o hardening explícito.
- **Recomendação**: após emitir, `accessTokens.delete(sha256(token))` ou rotacionar
  o `cNonce`; validar `iat` do proof (`maxTokenAge: '5m'`), impor
  `algorithms: ['ES256']` e conferir `header.typ === 'openid4vci-proof+jwt'`.

### A-13 — Verifier não impõe minimização: repassa disclosures não solicitadas

- **Severidade**: Média (privacidade).
- **Evidência**: `src/modules/verifier/routes.ts:82-88` monta `disclosed` a partir
  de TODAS as disclosures presentes no `vp_token`, sem cruzar com
  `session.requestedClaims`; o resultado é gravado em `resultClaims` (`:198`) e
  servido ao portal em `GET /verifier/sessions/:id` (`:222-226`).
- **Impacto**: se uma wallet (honesta demais ou maliciosa) enviar disclosures além
  das pedidas na `dcql_query`, o verifier as aceita e as expõe ao portal — falha de
  minimização de dados. No fluxo honesto a wallet só envia o selecionado, então o
  e2e passa e o risco prático é baixo; mas o enforcement do lado do verificador
  (exigido no checklist c) não existe.
- **Recomendação**: filtrar `disclosed` para conter apenas as chaves de
  `session.requestedClaims` (descartar extras) ou rejeitar a apresentação com
  disclosure não solicitada; adicionar teste negativo.

### A-14 — Wallet não valida a assinatura do issuer ao receber a credencial

- **Severidade**: Média.
- **Evidência**: `sovereignid-wallet/src/core/oid4vci.ts:174` — `receiveCredential`
  chama apenas `parseSdJwt`, que decodifica e confere os digests das disclosures
  (`src/core/sdjwt.ts:66-82`) mas **não verifica a assinatura ES256 do issuer** nem
  compara `iss` com o `credential_issuer` da oferta antes de armazenar. A função
  `verifyJwtSignature` (`src/core/crypto.ts:144`) existe e é testada
  (`scripts/core-tests.ts:132-163`), porém **nunca é usada no fluxo do app**.
- **Impacto**: a wallet confia cegamente na credencial retornada pelo
  `credential_endpoint`. No modelo da PoC o dano é limitado (a wallet fala com o
  `API_BASE_URL` fixo em canal local confiável), mas o checklist (g) exige a
  verificação e a amarração de `iss`; sem TLS/pinning, um MITM injetaria credencial
  forjada que a wallet armazenaria como válida.
- **Recomendação**: em `receiveCredential`, buscar o JWKS do issuer
  (`/.well-known/jwks.json`), chamar `verifyJwtSignature(parsed.jwt, issuerJwk)` e
  exigir `parsed.payload.iss === offer.credentialIssuer` (e `alg === ES256`) antes
  de `addCredential`.

## Baixo

### A-15 — Portal usa `innerHTML` com dados da apresentação/seed (XSS defensivo)

- **Severidade**: Baixa (não explorável hoje).
- **Evidência**: `web/index.html:219-223` injeta `<td>${k}</td><td>${v}</td>` via
  `innerHTML` com as claims divulgadas; `:240-248` faz o mesmo com os campos de
  `/sou-sp/servidores`.
- **Impacto**: as claims chegam de disclosures amarradas por digest a um SD-JWT
  assinado pelo issuer, e os servidores vêm do seed — ou seja, os valores não são
  arbitrariamente injetáveis por um atacante externo na PoC. Ainda assim, é o padrão
  clássico que vira XSS assim que uma fonte de dados deixar de ser confiável.
- **Recomendação**: usar `textContent`/`createElement` em vez de `innerHTML`, ou
  escapar os valores antes de interpolar. Custo baixo, boa higiene para a fase de
  produção.
