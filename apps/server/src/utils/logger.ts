/**
 * Structured content-free logger for NIZ Chat.
 * Redacts message bodies, tokens, and cryptographic keys.
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogContext {
  requestId?: string;
  senderPublicId?: string;
  recipientPublicId?: string;
  envelopeId?: string;
  method?: string;
  url?: string;
  statusCode?: number;
  durationMs?: number;
  [key: string]: unknown;
}

const REDACTED_KEYS = new Set([
  'ciphertext',
  'plaintext',
  'token',
  'invitationtoken',
  'privatekey',
  'secret',
  'key',
  'signature',
]);

function sanitize(obj: unknown): unknown {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sanitize);

  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (REDACTED_KEYS.has(k.toLowerCase())) {
      clean[k] = '[REDACTED]';
    } else if (typeof v === 'object' && v !== null) {
      clean[k] = sanitize(v);
    } else {
      clean[k] = v;
    }
  }
  return clean;
}

export const logger = {
  log(level: LogLevel, message: string, context?: LogContext): void {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      ...(context ? (sanitize(context) as object) : {}),
    };
    if (level === 'error') {
      console.error(JSON.stringify(entry));
    } else if (level === 'warn') {
      console.warn(JSON.stringify(entry));
    } else {
      console.log(JSON.stringify(entry));
    }
  },
  info(message: string, context?: LogContext): void {
    this.log('info', message, context);
  },
  warn(message: string, context?: LogContext): void {
    this.log('warn', message, context);
  },
  error(message: string, context?: LogContext): void {
    this.log('error', message, context);
  },
};
