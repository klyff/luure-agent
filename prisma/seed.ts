import 'dotenv/config';
import { createHash } from 'node:crypto';
import { PrismaClient } from '../src/generated/prisma/client.js';
import { PrismaPg } from '@prisma/adapter-pg';

const adapter = new PrismaPg({
  connectionString:
    process.env.DATABASE_URL ??
    'postgres://postgres:postgres@localhost:51214/template1?sslmode=disable',
});
const prisma = new PrismaClient({ adapter });

function fotoHash(seedText: string): string {
  return createHash('sha256').update(seedText).digest('hex');
}

export const servidoresSeed = [
  {
    cpf: '12345678901',
    nome: 'Ana Paula Ferreira',
    matricula: 'SEFAZ-118234',
    cargo: 'Agente Fiscal de Rendas',
    orgao: 'SEFAZ-SP',
    secretaria: 'Secretaria da Fazenda e Planejamento',
    vinculoAtivo: true,
    dataAdmissao: new Date('2012-03-15T00:00:00.000Z'),
    fotoHash: fotoHash('ana-paula-ferreira'),
    margemDisponivelCentavos: 285000, // R$ 2.850,00
    nivelContaGovbr: 'ouro',
  },
  {
    cpf: '23456789012',
    nome: 'Carlos Eduardo Souza',
    matricula: 'SEDUC-407551',
    cargo: 'Professor de Educação Básica II',
    orgao: 'SEDUC-SP',
    secretaria: 'Secretaria da Educação',
    vinculoAtivo: true,
    dataAdmissao: new Date('2016-02-01T00:00:00.000Z'),
    fotoHash: fotoHash('carlos-eduardo-souza'),
    margemDisponivelCentavos: 92000, // R$ 920,00
    nivelContaGovbr: 'ouro',
  },
  {
    cpf: '34567890123',
    nome: 'Mariana Oliveira Costa',
    matricula: 'SES-229876',
    cargo: 'Enfermeira',
    orgao: 'SES-SP',
    secretaria: 'Secretaria da Saúde',
    vinculoAtivo: true,
    dataAdmissao: new Date('2019-08-12T00:00:00.000Z'),
    fotoHash: fotoHash('mariana-oliveira-costa'),
    margemDisponivelCentavos: 38000, // R$ 380,00
    nivelContaGovbr: 'prata',
  },
  {
    cpf: '45678901234',
    nome: 'João Batista Ramos',
    matricula: 'PRODESP-88123',
    cargo: 'Analista de Tecnologia da Informação',
    orgao: 'PRODESP',
    secretaria: 'Secretaria de Gestão e Governo Digital',
    vinculoAtivo: false,
    dataAdmissao: new Date('2008-11-03T00:00:00.000Z'),
    fotoHash: fotoHash('joao-batista-ramos'),
    margemDisponivelCentavos: 0,
    nivelContaGovbr: 'ouro',
  },
  {
    cpf: '56789012345',
    nome: 'Regina Célia Almeida',
    matricula: 'SPPREV-51439',
    cargo: 'Técnico Previdenciário',
    orgao: 'SPPREV',
    secretaria: 'São Paulo Previdência',
    vinculoAtivo: true,
    dataAdmissao: new Date('2010-06-21T00:00:00.000Z'),
    fotoHash: fotoHash('regina-celia-almeida'),
    margemDisponivelCentavos: 176500, // R$ 1.765,00
    nivelContaGovbr: 'ouro',
  },
];

export async function seed(client = prisma): Promise<void> {
  for (const servidor of servidoresSeed) {
    await client.servidor.upsert({
      where: { cpf: servidor.cpf },
      update: servidor,
      create: servidor,
    });
  }
}

const isDirectRun = process.argv[1]?.endsWith('seed.ts');
if (isDirectRun) {
  seed()
    .then(async () => {
      const count = await prisma.servidor.count();
      console.log(`Seed concluído: ${count} servidores no banco.`);
      await prisma.$disconnect();
    })
    .catch(async (err) => {
      console.error(err);
      await prisma.$disconnect();
      process.exit(1);
    });
}
