import type { IStorageAdapter } from './interface.js';
import { MemoryStorageAdapter } from './memory.js';
import { PostgresStorageAdapter } from './postgres.js';
import { logger } from '../utils/logger.js';

export * from './interface.js';
export * from './memory.js';
export * from './postgres.js';

export function createStorageAdapter(): IStorageAdapter {
  const adapterType = process.env.STORAGE_ADAPTER?.toLowerCase();

  if (adapterType === 'postgres' || adapterType === 'postgresql') {
    logger.info('Initializing production PostgreSQL storage adapter', {
      adapter: 'postgres',
    });
    return new PostgresStorageAdapter();
  }

  logger.info('Initializing in-memory storage adapter for local dev & testing', {
    adapter: 'memory',
  });
  return new MemoryStorageAdapter();
}
