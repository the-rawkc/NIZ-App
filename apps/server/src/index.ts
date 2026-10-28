import dotenv from 'dotenv';
import { buildApp } from './app.js';
import { MemoryStorageAdapter } from './storage/memory.js';
import { logger } from './utils/logger.js';

dotenv.config();

const port = Number.parseInt(process.env.PORT || '4000', 10);
const host = process.env.HOST || '0.0.0.0';

// Storage adapter (Memory adapter default for dev/tests, easily swappable with Postgres)
const storage = new MemoryStorageAdapter();

async function main() {
  const app = await buildApp({ storage });

  try {
    await app.listen({ port, host });
    logger.info(`NIZ Chat Server running on http://${host}:${port}`);
  } catch (err) {
    logger.error('Failed to start server', { err });
    process.exit(1);
  }
}

main();
