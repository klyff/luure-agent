# Modelo de Ameaças — PoC SOU.SP 2.0 (Onda 2)

> Agente de segurança — Onda 2. Escopo: `sovereignid-wallet` (holder) e
> `sovereignid-agent-server` (mock IdP gov.br + Issuer OID4VCI + Verifier OID4VP +
> Token Status List). Snapshot do código em 2026-07-06: servidor com módulos
> `govbr-mock` e `sou-sp` implementados; Issuer/Verifier/Status List ainda em
> desenvolvimento (analisados pela spec do `CONTRACTS.md`). Wallet ainda na Onda 1
> (UI com mocks, sem material criptográfico no dispositivo).
>
> Este documento é ENXUTO por decisão: só ameaças concretas deste sistema, não
> catálogo genérico. Postura: PoC local, sem produção — riscos aceitos estão
> explícitos na tabela ao final.

## 1. Ativos

| Ativo | Onde vive | Impacto se comprometido |
|---|---|---|
| **Chave privada do holder (P-256)** | Wallet, expo-secure-store (Onda 2; ainda não implementada) | Impersonação total do servidor público: assinar proofs de emissão e KB-JWTs em nome da vítima |
| **Chave privada do issuer (ES256)** | `keys/issuer.jwk.json` (arquivo local, JWK com `d`) | Forjar Carteiras Funcionais e margens consignáveis arbitrárias, aceitas por qualquer verifier |
| **Chave privada do mock gov.br (ES256)** | `keys/govbr.jwk.json` | Forjar `id_token` gov.br (na PoC o mock já não autentica de verdade — ver riscos aceitos) |
| **Credenciais SD-JWT VC + disclosures** | Wallet (Onda 2: SecureStore); hash em `CredentialIssued.sdJwtHash` | Exposição de PII e possibilidade de replay se KB-JWT não for exigido |
| **PII dos servidores** (CPF, nome, matrícula, cargo, margem) | `dev.db` (SQLite plano), seed em `prisma/seed.ts`, resposta de `/sou-sp/servidores` | Vazamento de dados pessoais; na PoC são dados FICTÍCIOS do seed |
| **Nonces / codes efêmeros** | `c_nonce` (issuer), `nonce`/`state` (verifier, `VerificationSession`), `pre-authorized_code`/`tx_code` (`CredentialOffer`), auth code + PKCE (Maps em memória do govbr-mock) | Replay de apresentações, roubo de oferta de credencial, sequestro de login |
| **Tokens de acesso** | `access_token` do issuer e do mock gov.br (Bearer opacos) | Emissão de credencial em nome de outrem / leitura de userinfo |

## 2. Atores e fluxos

- **Holder**: servidor público com a wallet (React Native/Expo).
- **Issuer**: agent-server emitindo SD-JWT VC via OID4VCI pre-authorized code.
- **Verifier**: agent-server (portal demo) via OID4VP `direct_post`.
- **Mock IdP gov.br**: OIDC authorization code + PKCE, no mesmo servidor.
- **Atacante considerado**: (i) alguém na mesma rede local/Wi-Fi da demo; (ii) verifier malicioso ou curioso; (iii) quem apresenta um QR/deeplink falso ao holder; (iv) quem obtém o dispositivo do holder; (v) quem obtém acesso de leitura à máquina de desenvolvimento.

Fluxos: **F1** login gov.br mock → **F2** emissão OID4VCI (offer → token → credential) → **F3** apresentação OID4VP (request → seleção de disclosures → direct_post) → **F4** revogação/status list.

## 3. Ameaças por categoria STRIDE

### S — Spoofing (falsificação de identidade)

| # | Cenário concreto | Mitigação na PoC | Necessário em produção |
|---|---|---|---|
| S1 | **Phishing de credential offer**: QR falso com `credential_offer_uri` apontando para um issuer atacante; a wallet emite proof e armazena uma credencial forjada, ou envia `tx_code` real a um endpoint falso | Nenhuma no código atual (`scan.tsx` apenas captura o valor). Mitigação prevista: wallet só confia no `API_BASE_URL` fixo (`src/services/config.ts`) | Allowlist de issuers confiáveis (trust framework), exibição clara da origem ao usuário, validação do `credential_issuer` contra metadata assinada |
| S2 | **Verifier falso** apresenta `request_uri` de terceiro; holder revela claims a quem não devia | Nenhuma; deeplink `openid4vp://` aceita qualquer `request_uri` pela spec | Client ID scheme com registro/certificados de verifier (ex.: `x509_san_dns`), tela de consentimento mostrando identidade verificada do solicitante |
| S3 | **Login como qualquer servidor**: o mock gov.br autentica só com CPF do seed (`/govbr/authorize?cpf=...`), sem senha/biometria | Nenhuma — é o propósito do mock | gov.br real (OIDC com autenticação forte, níveis prata/ouro reais, `amr` verdadeiro) |
| S4 | **Proof JWT de emissão forjado/replay**: atacante com um `access_token` vazado envia proof com chave própria e recebe credencial com `cnf` dele | Spec exige `aud`=issuer e `nonce`=`c_nonce`; código do issuer ainda não existe — **item obrigatório do Gate 2** (CHECKLIST item a) | Idem + `c_nonce` single-use com expiração curta, attestation de wallet |

### T — Tampering (adulteração)

| # | Cenário concreto | Mitigação na PoC | Necessário em produção |
|---|---|---|---|
| T1 | **Adulteração de claims da credencial** (ex.: mudar `margem_disponivel_centavos`) | Assinatura ES256 do issuer sobre o SD-JWT; disclosures ligadas por digest (biblioteca `@sd-jwt/*`) | Igual, + HSM/KMS protegendo a chave |
| T2 | **Troca de disclosures entre credenciais** (mix-and-match de outra credencial do mesmo holder) | Digests `_sd` amarram disclosure ao JWT; `sd_hash` do KB-JWT amarra o conjunto apresentado — verificar no Gate 2 (código do verifier ainda não existe) | Igual |
| T3 | **Edição direta do `dev.db`** (ex.: setar `revoked=false`, mudar `vinculoAtivo`) por quem tem acesso à máquina | Nenhuma — SQLite em arquivo com permissão de usuário; risco aceito | Postgres com controle de acesso, trilha de auditoria, backups íntegros |
| T4 | **MITM na rede local** altera respostas HTTP (tudo é `http://localhost:3100` sem TLS) | Nenhuma; risco aceito (tráfego local simulador↔host) | TLS obrigatório em todos os endpoints; certificate pinning na wallet |

### R — Repudiation (repúdio)

| # | Cenário concreto | Mitigação na PoC | Necessário em produção |
|---|---|---|---|
| R1 | Servidor nega ter apresentado a credencial a um verifier; ou órgão nega ter revogado | Nenhum log de auditoria (`Fastify({ logger: false })` em `src/app.ts:11`); `VerificationSession` guarda resultado, `CredentialIssued.updatedAt` marca revogação | Log de auditoria imutável e assinado dos eventos de emissão/apresentação/revogação, sem PII desnecessária |
| R2 | Emissão contestada ("nunca pedi essa credencial") | `CredentialOffer`/`CredentialIssued` no banco associam CPF→emissão | Consentimento explícito registrado, `tx_code` obrigatório entregue por canal separado |

### I — Information Disclosure (vazamento de informação)

| # | Cenário concreto | Mitigação na PoC | Necessário em produção |
|---|---|---|---|
| I1 | **Vazamento do `dev.db`**: arquivo mode 0644 com CPF, margem e vínculo de todos os servidores | Dados são FICTÍCIOS (seed); `dev.db*` no `.gitignore` | Banco cifrado em repouso, PII minimizada/tokenizada, controle de acesso |
| I2 | **`/sou-sp/servidores` expõe CPF completo sem auth** (`src/modules/sou-sp/routes.ts:19`, comentário admite "apenas para demo") | Risco aceito, dados fictícios | Endpoint autenticado; nunca retornar CPF completo |
| I3 | **Disclosures além do solicitado**: wallet envia todas as disclosures em vez das selecionadas; ou verifier retorna ao portal claims não pedidas na `dcql_query` | Tela `present.tsx` já modela seleção por claim (Onda 1, mock); enforcement real — Gate 2 (CHECKLIST item c) | Igual + teste automatizado de minimização |
| I4 | **PII em logs**: `scan.tsx:22` loga conteúdo do QR e `present.tsx:45` loga claims compartilhadas no console | Logger do servidor desativado; logs da wallet só em dev — **remover antes do build final** (FINDINGS A-05) | Política de logging sem PII, revisão automatizada |
| I5 | **Correlação entre verifiers**: mesma assinatura de issuer + mesmo `cnf.jwk` permitem rastrear o holder entre apresentações | Nenhuma — inerente a SD-JWT VC com credencial única; aceito na PoC | Emissão em lote (batch) com chaves/credenciais de uso único |
| I6 | **Chaves privadas legíveis**: `keys/*.jwk.json` mode 0644 com o campo `d` em claro | `keys/` no `.gitignore`; risco aceito | HSM/KMS; nunca chave privada em arquivo |

### D — Denial of Service

| # | Cenário concreto | Mitigação na PoC | Necessário em produção |
|---|---|---|---|
| D1 | **Revogação maliciosa**: `POST /admin/revoke` sem auth permite a qualquer um na rede revogar a credencial de qualquer servidor (CONTRACTS §4) | Nenhuma — risco aceito e documentado no contrato | Autenticação forte + autorização por papel + auditoria no endpoint de revogação |
| D2 | Flood de `POST /verifier/sessions` ou `/issuer/credential-offers` enche o SQLite / gera QRs sem limite | Nenhuma (sem rate limit) | Rate limiting, autenticação dos endpoints demo/admin |
| D3 | Maps em memória do govbr-mock (`authCodes`, `accessTokens` em `govbr-mock/routes.ts:21-22`) crescem sem GC de expirados | TTL verificado na leitura, mas entradas expiradas nunca são removidas | Store com TTL real (Redis) ou limpeza periódica |

### E — Elevation of Privilege

| # | Cenário concreto | Mitigação na PoC | Necessário em produção |
|---|---|---|---|
| E1 | **Replay de vp_token entre verifiers**: verifier malicioso captura uma apresentação válida e a reapresenta a outro verifier | KB-JWT com `aud`=client_id do verifier e `nonce` da sessão (spec); verifier ainda não implementado — **Gate 2 (CHECKLIST item b)** | Igual + nonce single-use persistido e janela de `iat` curta |
| E2 | **Roubo do dispositivo**: quem tem o aparelho desbloqueado apresenta credenciais como o titular | Onda 2 prevê biometria via `expo-local-authentication` antes de assinar KB-JWT (ainda não implementado) | Chave em Secure Enclave/StrongBox não-exportável, exigindo biometria por operação de assinatura |
| E3 | **Interceptação do authorization code** do mock gov.br: o `redirect_uri` NÃO é validado contra allowlist (`govbr-mock/routes.ts:138-143`; `config.walletRedirectUris` existe mas não é usado) — um link de authorize forjado envia o code a um endpoint do atacante | PKCE S256 limita o dano: sem o `code_verifier` correspondente o code não vira token. Mas se o atacante controla o link inteiro (challenge dele), obtém tokens de qualquer CPF do seed — que o mock já permite por design | Allowlist estrita de `redirect_uri` + validação de `redirect_uri` no token endpoint (recomendado corrigir já na Onda 2 — custo baixo, ver FINDINGS A-01) |
| E4 | **Oferta interceptada**: quem fotografa o QR de oferta antes do titular resgata a credencial (pre-authorized code é bearer) | `tx_code` existe no modelo (`CredentialOffer.txCode`) mas é OPCIONAL no token endpoint pela spec — risco aceito | `tx_code` obrigatório entregue fora de banda; código single-use com expiração curta (single-use já previsto pelo `status: claimed`) |

## 4. Riscos aceitos na PoC

Aceitos conscientemente porque a PoC roda local, com dados fictícios, para demonstrar o protocolo. **Nenhum destes pode ir para produção.**

| ID | Risco aceito | Evidência | Justificativa | Produção |
|---|---|---|---|---|
| RA-01 | `POST /admin/revoke` sem autenticação | `CONTRACTS.md` §4 (endpoint ainda não implementado) | Demo de revogação em tempo real sem fricção | AuthN/AuthZ + auditoria |
| RA-02 | Chaves privadas do issuer e do gov.br em arquivos JWK locais, extraíveis, mode 0644 | `keys/issuer.jwk.json` (campo `d` presente), `src/lib/keys.ts:21-29` | Simplicidade da PoC; `keys/` está no `.gitignore` | HSM/KMS, rotação de chaves |
| RA-03 | HTTP sem TLS em todos os endpoints | `src/lib/config.ts:3-5` (`http://localhost:3100`) | Tráfego local simulador↔host | TLS + pinning |
| RA-04 | Chave do holder em `expo-secure-store` como bytes exportáveis (P-256 via `@noble/curves` em JS), não em Secure Enclave | Planejado para Onda 2 (deps em `package.json` da wallet; código ainda não existe) | Expo Go não expõe Secure Enclave; PoC prioriza portabilidade | Chave de hardware não-exportável com biometria por uso |
| RA-05 | `tx_code` opcional no token endpoint do issuer | `CONTRACTS.md` §2 (`tx_code` (opcional na PoC)) | Facilitar a demo com QR único | `tx_code` obrigatório fora de banda |
| RA-06 | Mock gov.br autentica apenas com CPF do seed, sem credencial | `src/modules/govbr-mock/routes.ts:145-176` | É um mock de IdP | gov.br real |
| RA-07 | `/sou-sp/servidores` expõe CPF completo e margem sem auth | `src/modules/sou-sp/routes.ts:19` | Tela demo do portal; dados fictícios | Remover/autenticar |
| RA-08 | CORS `origin: true` (qualquer origem) | `src/app.ts:14` | Dev web da wallet em porta variável | Allowlist de origens |
| RA-09 | SQLite `dev.db` sem cifra, PII fictícia em claro | `prisma/schema.prisma`, arquivo `dev.db` 0644 | PoC local | Banco gerenciado, cifrado, acesso mínimo |
| RA-10 | Sem rate limiting nem log de auditoria | `src/app.ts:11` (`logger: false`) | Escopo da demo | Rate limit + auditoria assinada |
