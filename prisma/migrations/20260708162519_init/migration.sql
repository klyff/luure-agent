-- CreateTable
CREATE TABLE "Servidor" (
    "id" TEXT NOT NULL,
    "cpf" TEXT NOT NULL,
    "nome" TEXT NOT NULL,
    "matricula" TEXT NOT NULL,
    "cargo" TEXT NOT NULL,
    "orgao" TEXT NOT NULL,
    "secretaria" TEXT NOT NULL,
    "vinculoAtivo" BOOLEAN NOT NULL,
    "dataAdmissao" TIMESTAMP(3) NOT NULL,
    "fotoHash" TEXT NOT NULL,
    "margemDisponivelCentavos" INTEGER NOT NULL,
    "nivelContaGovbr" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Servidor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CredentialOffer" (
    "id" TEXT NOT NULL,
    "preAuthorizedCode" TEXT NOT NULL,
    "txCode" TEXT NOT NULL,
    "vct" TEXT NOT NULL,
    "servidorCpf" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CredentialOffer_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CredentialIssued" (
    "id" TEXT NOT NULL,
    "vct" TEXT NOT NULL,
    "servidorCpf" TEXT NOT NULL,
    "statusListIndex" INTEGER NOT NULL,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "sdJwtHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CredentialIssued_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EphemeralEntry" (
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EphemeralEntry_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "VerificationSession" (
    "id" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "vct" TEXT NOT NULL,
    "requestedClaims" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "resultClaims" TEXT,
    "reason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "VerificationSession_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Servidor_cpf_key" ON "Servidor"("cpf");

-- CreateIndex
CREATE UNIQUE INDEX "Servidor_matricula_key" ON "Servidor"("matricula");

-- CreateIndex
CREATE INDEX "Servidor_matricula_idx" ON "Servidor"("matricula");

-- CreateIndex
CREATE INDEX "Servidor_orgao_idx" ON "Servidor"("orgao");

-- CreateIndex
CREATE UNIQUE INDEX "CredentialOffer_preAuthorizedCode_key" ON "CredentialOffer"("preAuthorizedCode");

-- CreateIndex
CREATE INDEX "CredentialOffer_servidorCpf_idx" ON "CredentialOffer"("servidorCpf");

-- CreateIndex
CREATE INDEX "CredentialOffer_status_idx" ON "CredentialOffer"("status");

-- CreateIndex
CREATE UNIQUE INDEX "CredentialIssued_statusListIndex_key" ON "CredentialIssued"("statusListIndex");

-- CreateIndex
CREATE INDEX "CredentialIssued_servidorCpf_idx" ON "CredentialIssued"("servidorCpf");

-- CreateIndex
CREATE INDEX "CredentialIssued_vct_idx" ON "CredentialIssued"("vct");

-- CreateIndex
CREATE INDEX "EphemeralEntry_expiresAt_idx" ON "EphemeralEntry"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "VerificationSession_state_key" ON "VerificationSession"("state");

-- CreateIndex
CREATE INDEX "VerificationSession_status_idx" ON "VerificationSession"("status");
