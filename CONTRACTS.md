# CONTRACTS.md — Contrato Wallet ↔ Agent Server (PoC SOU.SP 2.0)

Este documento é a fonte de verdade dos contratos de API entre `sovereignid-wallet`
(React Native) e `sovereignid-agent-server` (Node/Fastify). Qualquer mudança deve ser
refletida aqui ANTES de alterar o código.

Base URL (dev): `http://localhost:3100` (no simulador iOS use `localhost`; no emulador
Android use `http://10.0.2.2:3100`).

Formato de credencial: **SD-JWT VC** (`dc+sd-jwt`), assinatura **ES256**.
Holder binding: claim `cnf.jwk` com a chave pública P-256 da wallet; apresentações
carregam Key Binding JWT (KB-JWT). O payload inclui `jti` (id do registro
`CredentialIssued`), usado como `credential_id` em `/admin/revoke`.

## Tipos de credencial (vct)

| vct | Descrição | Claims (todas seletivamente divulgáveis, exceto `vct`, `iss`, `cnf`) |
|---|---|---|
| `urn:sovereignid:sp:funcional` | Carteira Funcional Digital do servidor público SP | `nome`, `cpf_mascarado`, `matricula`, `cargo`, `orgao`, `secretaria`, `vinculo_ativo` (bool), `data_admissao`, `foto_hash` |
| `urn:sovereignid:sp:margem-consignavel` | Margem consignável | `matricula`, `margem_disponivel_centavos` (int), `faixa_margem` (`"ATE_500"`, `"500_A_1500"`, `"ACIMA_1500"`), `competencia` (`YYYY-MM`) |

## 1. Mock IdP gov.br (OIDC, authorization code + PKCE)

- `GET /govbr/.well-known/openid-configuration`
- `GET /govbr/authorize?client_id&redirect_uri&code_challenge&code_challenge_method=S256&state&scope=openid&cpf=<cpf-do-seed>` — página HTML de login fake; em modo API, aceita `cpf` direto e redireciona com `code`.
- `POST /govbr/token` — `grant_type=authorization_code`, retorna `{ access_token, id_token, token_type, expires_in }`. `id_token` inclui `amr`, `nivel_conta` (`"prata"` | `"ouro"`).
- `GET /govbr/userinfo` — Bearer; retorna `{ sub (cpf), name, nivel_conta }`.

Client registrado para a wallet: `client_id=sovereignid-wallet`, `redirect_uri=sovereignid://govbr/callback` (e `http://localhost:8081/govbr/callback` para dev web).

## 2. Issuer (OID4VCI, fluxo pre-authorized code)

- `GET /.well-known/openid-credential-issuer` — metadata: `credential_issuer`, `credential_endpoint`, `token_endpoint`, `credential_configurations_supported` (as duas vct acima, formato `dc+sd-jwt`).
- `GET /.well-known/jwks.json` — chaves públicas do issuer.
- `POST /issuer/credential-offers` — (demo/admin) body `{ cpf, vct }`. Cria oferta para servidor do seed. Retorna:
  `{ id, credential_offer_uri, offer_deeplink, qrcode_png_base64, pre_authorized_code, tx_code }`.
  `offer_deeplink` = `openid-credential-offer://?credential_offer_uri=<url-encoded>`.
- `GET /issuer/credential-offer/{id}` — dereference: objeto `credential_offer` padrão OID4VCI com `grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]`.
- `POST /issuer/token` — form: `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`, `pre-authorized_code`, `tx_code` (opcional na PoC). Retorna `{ access_token, token_type, expires_in, c_nonce }`.
- `POST /issuer/credential` — Bearer access_token. Body:
  `{ vct, proof: { proof_type: "jwt", jwt } }` onde `jwt` é assinado pela chave da wallet,
  `aud` = credential_issuer, `nonce` = `c_nonce`. Retorna `{ credentials: [{ credential: "<sd-jwt-vc compacto>" }] }`.
  Erros: `400 invalid_proof` (nonce/aud errados), `401 invalid_token`.

## 3. Verifier (OID4VP, response_mode direct_post)

- `POST /verifier/sessions` — (demo/portal) body `{ vct, requested_claims: string[] }`.
  Retorna `{ id, request_uri, request_deeplink, qrcode_png_base64 }`.
  `request_deeplink` = `openid4vp://?request_uri=<url-encoded>`.
- `GET /verifier/request/{id}` — Authorization Request (JSON): `{ client_id, response_uri, response_type: "vp_token", response_mode: "direct_post", nonce, state, dcql_query }`. `dcql_query.credentials[0] = { id, format: "dc+sd-jwt", meta: { vct_values: [vct] }, claims: [{ path: [claim] }...] }`.
- `POST /verifier/direct_post` — form: `vp_token` (SD-JWT VC + disclosures selecionadas + KB-JWT), `state`.
  Server valida: assinatura issuer, status list (revogação), KB-JWT (nonce, aud, iat, binding cnf.jwk). Retorna `{ status: "verified" | "rejected", reason? }`.
- `GET /verifier/sessions/{id}` — poll do portal: `{ status: "pending" | "verified" | "rejected", claims?, reason? }`.

## 4. Status list / revogação

- `GET /status/token-status-list` — JWT (IETF Token Status List) com bits de status.
- `POST /admin/revoke` — body `{ credential_id }` → marca revogada. (Sem auth na PoC; documentado como risco aceito.)

## 5. SOU.SP (dados simulados)

- `GET /sou-sp/servidores` — lista do seed (nome, cpf, matricula, cargo, orgao, secretaria, margem).

## Convenções

- Erros JSON: `{ error: string, error_description?: string }` com status HTTP adequado.
- IDs: cuid. Datas: ISO-8601 UTC.
- QR codes sempre também disponíveis como deeplink em texto para digitar no simulador.
