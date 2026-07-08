import type { FastifyInstance } from 'fastify';
import { prisma } from '../../lib/db.js';

export function maskCpf(cpf: string): string {
  // "12345678901" -> "***.456.789-**" (mantém os 6 dígitos do meio)
  return `***.${cpf.slice(3, 6)}.${cpf.slice(6, 9)}-**`;
}

export async function souSpRoutes(app: FastifyInstance): Promise<void> {
  app.get('/sou-sp/servidores', async () => {
    const servidores = await prisma.servidor.findMany({
      orderBy: { nome: 'asc' },
    });
    return servidores.map((s) => ({
      id: s.id,
      nome: s.nome,
      cpfMascarado: maskCpf(s.cpf),
      // cpf completo exposto apenas para fins de demo da PoC
      cpf: s.cpf,
      matricula: s.matricula,
      cargo: s.cargo,
      orgao: s.orgao,
      secretaria: s.secretaria,
      vinculoAtivo: s.vinculoAtivo,
      dataAdmissao: s.dataAdmissao.toISOString(),
      fotoHash: s.fotoHash,
      margemDisponivelCentavos: s.margemDisponivelCentavos,
      nivelContaGovbr: s.nivelContaGovbr,
    }));
  });
}
