# Gate Final de Segurança — Onda 3 (review final)

PoC de identidade soberana SOU.SP 2.0 · `luure-agent-server` +
`luure-wallet-reactnative` · Review linha a linha do código criptográfico e de
protocolo (OID4VCI / OID4VP / SD-JWT VC / Token Status List). Data: 2026-07-06.

---

## Veredito: ✅ APROVADO COM RESSALVAS

O código final implementa corretamente os três pilares que sustentam a
demonstração: **autenticidade** (o verifier valida de fato a assinatura ES256 do
issuer sobre o SD-JWT, sem confiança implícita), **binding de posse** (o KB-JWT é
verificado contra a `cnf.jwk` da própria credencial, com `aud`, `nonce` de sessão
single-use, `iat` e `sd_hash` conferidos pela biblioteca `@sd-jwt/*`) e
**revogação verificável** (status list assinada + checagem do bit antes de
`verified`). Os achados da rodada anterior de alto/médio impacto (A-01, A-02,
A-03, A-05) foram corrigidos, o fluxo completo emissão → apresentação seletiva →
revogação passa no e2e, e não há nenhum defeito explorável que quebre
autenticidade, binding ou confidencialidade dentro do modelo de ameaça da PoC —
logo **não há bloqueador de gate**. As ressalvas são três achados de severidade
média (`c_nonce` reutilizável no issuer, minimização não imposta pelo verifier,
wallet não valida a assinatura do issuer ao receber) e um baixo (`innerHTML` no
portal), todos de baixo impacto prático na PoC mas que **devem** ser resolvidos
antes de produção.

---

## Tabela-resumo dos checks (a)–(h)

| Item | Check | Status | Evidência principal |
|---|---|---|---|
| (a) | Proof JWT de emissão (aud, nonce, binding chave↔`cnf`, single-use) | ⚠️ Parcial | `issuer/routes.ts:299-355` — binding e pre-auth single-use OK; `c_nonce` reutilizável (**A-12**) |
| (b) | KB-JWT (aud, nonce single-use, iat, sd_hash, assinatura via `cnf.jwk`, typ) | ✅ Coberto | `verifier/routes.ts:36-58`; `lib/sdjwt.ts:65-68`; `@sd-jwt/core:752-756,1310-1317` |
| (c) | Minimização de disclosures (wallet envia só o selecionado; verifier filtra) | ⚠️ Parcial | wallet OK `wallet/core/sdjwt.ts:115-118`; verifier não filtra (**A-13**) `verifier/routes.ts:82-88` |
| (d) | Status list consultada na verificação (revogação → rejected) | ✅ Coberto | `verifier/routes.ts:60-80`; `status/routes.ts:36-43`; `oid4vc.test.ts:339-342` |
| (e) | PKCE S256 (server impõe; wallet gera com CSPRNG, valida `state`) | ✅ Coberto | `govbr-mock/routes.ts:151,237-242`; `wallet/app/login.tsx:24-25,40,66-68` |
| (f) | `state`/`nonce`/codes imprevisíveis (CSPRNG, sem `Math.random`) | ✅ Coberto | `issuer/routes.ts:162,256,257`; `verifier/routes.ts:121-122`; `secure-key-store.ts:21-24` |
| (g) | Assinatura do issuer validada via JWKS (verifier + wallet ao receber) | ⚠️ Parcial | verifier OK `lib/sdjwt.ts:72-80`; wallet não valida (**A-14**) `wallet/core/oid4vci.ts:174` |
| (h) | Nenhuma PII em logs (ambos os repos) | ✅ Coberto | `app.ts:11`; `console.log` de scan/present removidos (grep) |

Placar: **5 ✅ · 3 ⚠️ · 0 ❌**.

---

## Achados novos da Onda 3 (por severidade)

| ID | Sev. | Resumo | Ref. |
|---|---|---|---|
| A-12 | Médio | `c_nonce`/access_token reutilizáveis dentro do TTL; proof sem janela de `iat`, sem `algorithms` allowlist nem checagem de `typ` | FINDINGS §Review final |
| A-13 | Médio | Verifier repassa ao portal disclosures não solicitadas (minimização não imposta no lado servidor) | FINDINGS §Review final |
| A-14 | Médio | Wallet não valida a assinatura do issuer (nem `iss`) ao receber a credencial — confia cegamente | FINDINGS §Review final |
| A-15 | Baixo | Portal usa `innerHTML` com dados da apresentação/seed (XSS defensivo; não explorável hoje) | FINDINGS §Review final |

Contagem: **0 críticos · 0 altos · 3 médios · 1 baixo**.

Corrigidos desde a Onda 2: **A-01, A-02, A-03, A-05** (ver FINDINGS).

---

## Riscos aceitos da PoC (reafirmados — nenhum vai para produção)

Herdados do THREAT_MODEL (RA-01 a RA-10) e confirmados no código final:

- **RA-01** `POST /admin/revoke` sem autenticação (`status/routes.ts:50-72`).
- **RA-02** Chaves privadas do issuer/gov.br em arquivos JWK locais, extraíveis
  (`lib/keys.ts:22-30`).
- **RA-03** HTTP sem TLS em todos os endpoints (`lib/config.ts:3`).
- **RA-04** Chave do holder em `expo-secure-store` como hex exportável,
  `requireAuthentication:false`, gerada em software (`secure-key-store.ts:41-57`) —
  não em Secure Enclave/StrongBox.
- **RA-05** `tx_code` opcional no token endpoint do issuer
  (`issuer/routes.ts:246-249`).
- **RA-06** Mock gov.br autentica só com CPF do seed, sem credencial.
- **RA-07** `/sou-sp/servidores` expõe CPF completo sem auth
  (`sou-sp/routes.ts:18-19`); o portal ainda usa o CPF completo no botão de emissão
  (`web/index.html:247`).
- **RA-08** CORS `origin:true` (`app.ts:14`).
- **RA-09** SQLite `dev.db` sem cifra, PII fictícia em claro.
- **RA-10** Sem rate limiting nem log de auditoria (`app.ts:11`).

Aceitos adicionalmente na Onda 3 (baixo impacto na PoC, corrigir em produção):
- Verifier consulta o bit de revogação direto no banco em vez de validar o JWT da
  status list (aceitável por ser o mesmo processo; documentado em
  `verifier/routes.ts:30-32`).
- `nextStatusListIndex` via `aggregate max` e `direct_post` via `findUnique`+`update`
  fora de transação — corridas teóricas sob concorrência, irrelevantes na demo
  sequencial.
- A-12/A-13/A-14/A-15 aceitos **apenas** para a demo; entram como pré-requisitos
  da fase de produção.

---

## Top-5 requisitos de segurança para a fase de produção

1. **Chave do holder em hardware (Secure Enclave / StrongBox), não-exportável.**
   Substituir a chave em software persistida em hex (`secure-key-store.ts`) por
   chave P-256 gerada e mantida no elemento seguro, com assinatura exigindo
   biometria por operação. Fecha RA-04 e E2 do threat model.
2. **TLS obrigatório + certificate pinning na wallet.** Todo tráfego hoje é
   `http://localhost` (RA-03); em produção, HTTPS em todos os endpoints e pinning
   no app. Isso também é o que torna A-14 (wallet validar assinatura do issuer)
   plenamente eficaz contra MITM.
3. **Autenticação/autorização nos endpoints administrativos e de demo.**
   `POST /admin/revoke` (RA-01), `/sou-sp/servidores` (RA-07) e a emissão de ofertas
   precisam de authN forte + authZ por papel + trilha de auditoria assinada.
4. **Chave do issuer em HSM/KMS, com rotação.** Remover `keys/*.jwk.json` com o
   campo `d` em disco (RA-02); assinatura de credenciais e da status list feita no
   HSM, JWKS com múltiplas chaves e `kid` para rotação.
5. **Attestation de wallet e de plataforma (App Attest / Play Integrity).** Garantir
   no issuer que o proof vem de uma wallet legítima em dispositivo íntegro (fecha
   S1/S4), acompanhado de `c_nonce` single-use com expiração curta (A-12) e da
   allowlist de issuers/verifiers confiáveis (trust framework — S1/S2).

---

## Pré-requisitos técnicos imediatos (antes de "produção-ready", além do top-5)

- Corrigir **A-12**: invalidar/rotacionar `c_nonce` após emissão; validar `iat`,
  `typ` e `algorithms:['ES256']` do proof.
- Corrigir **A-13**: verifier filtra disclosures ao conjunto de `requested_claims`.
- Corrigir **A-14**: wallet verifica assinatura do issuer + `iss` ao receber.
- Corrigir **A-15**: portal usa `textContent`/escape em vez de `innerHTML`.
