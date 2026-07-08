import { prisma } from './db.js';

/**
 * Estado efêmero (auth codes, access tokens) persistido no banco.
 * Em serverless cada request pode cair em outra instância, então Maps em
 * memória não funcionam entre o /token e o /credential, por exemplo.
 */
export async function ephemeralSet(
  key: string,
  value: unknown,
  ttlMs: number,
): Promise<void> {
  const data = {
    value: JSON.stringify(value),
    expiresAt: new Date(Date.now() + ttlMs),
  };
  await prisma.ephemeralEntry.upsert({
    where: { key },
    update: data,
    create: { key, ...data },
  });
}

export async function ephemeralGet<T>(key: string): Promise<T | undefined> {
  const entry = await prisma.ephemeralEntry.findUnique({ where: { key } });
  if (!entry) return undefined;
  if (entry.expiresAt.getTime() < Date.now()) {
    await prisma.ephemeralEntry.delete({ where: { key } }).catch(() => {});
    return undefined;
  }
  return JSON.parse(entry.value) as T;
}

export async function ephemeralDelete(key: string): Promise<void> {
  await prisma.ephemeralEntry.deleteMany({ where: { key } });
}
