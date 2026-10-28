/**
 * Aggregate telemetry and metrics.
 * INVARIANT: Strictly aggregate counters; zero message bodies or contact graphs.
 */

export interface SystemHealthMetrics {
  status: 'healthy' | 'degraded' | 'down';
  uptimeSeconds: number;
  activeWebSocketConnections: number;
  queuedMessagesTotal: number;
  registeredAccountsEstimate: number;
  errorRateLastHour: number;
  version: string;
}
