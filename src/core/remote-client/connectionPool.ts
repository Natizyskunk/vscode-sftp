import logger from '../../logger';

export interface PoolOptions {
  /**
   * Максимальное количество одновременных соединений (default: 4)
   */
  maxConnections: number;
  /**
   * Максимальное количество попыток переподключения (default: 3)
   */
  retryCount: number;
  /**
   * Задержка перед повторным подключением в мс (default: 3000)
   */
  retryDelay: number;
}

const DEFAULT_POOL_OPTIONS: PoolOptions = {
  maxConnections: 4,
  retryCount: 3,
  retryDelay: 3000,
};

/**
 * Ошибки, при которых нужно переподключаться (не сдаваться)
 */
const RETRYABLE_ERROR_CODES = [
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'ENETUNREACH',
];

const RETRYABLE_ERROR_MESSAGES = [
  'socket hang up',
  'connection refused',
  'read ECONNRESET',
  'write ECONNRESET',
  'connection timed out',
  'connection lost',
  'not connected',
  'No response from server',
];

/**
 * Проверяет, является ли ошибка "переподключаемой"
 */
export function isRetryableError(err: Error & { code?: string }): boolean {
  if (err.code && RETRYABLE_ERROR_CODES.includes(err.code)) {
    return true;
  }
  const msg = (err.message || '').toLowerCase();
  return RETRYABLE_ERROR_MESSAGES.some(pattern => msg.includes(pattern.toLowerCase()));
}

/**
 * Счётчик активных соединений по хосту
 */
class ConnectionCounter {
  private _counts: Map<string, number> = new Map();

  private _key(host: string, port: number): string {
    return `${host}:${port}`;
  }

  increment(host: string, port: number) {
    const key = this._key(host, port);
    this._counts.set(key, (this._counts.get(key) || 0) + 1);
  }

  decrement(host: string, port: number) {
    const key = this._key(host, port);
    const current = this._counts.get(key) || 0;
    this._counts.set(key, Math.max(0, current - 1));
  }

  get(host: string, port: number): number {
    return this._counts.get(this._key(host, port)) || 0;
  }
}

// Глобальный счётчик соединений (shared across all service instances)
const globalConnectionCounter = new ConnectionCounter();

/**
 * Выполняет задачу с авторестартом при разрыве соединения.
 *
 * @param task - асинхронная функция, которую нужно выполнить
 * @param reconnect - функция переподключения
 * @param opts - параметры пула
 */
export async function executeWithRetry<T>(
  task: () => Promise<T>,
  reconnect: () => Promise<void>,
  opts: Partial<PoolOptions> = {},
): Promise<T> {
  const options = { ...DEFAULT_POOL_OPTIONS, ...opts };
  let attempt = 0;

  while (attempt <= options.retryCount) {
    try {
      return await task();
    } catch (err) {
      const error = err as Error & { code?: string };

      if (attempt >= options.retryCount || !isRetryableError(error)) {
        throw error;
      }

      attempt++;
      logger.warn(
        `[ConnectionPool] Connection error: "${error.message}". ` +
        `Retrying in ${options.retryDelay}ms (attempt ${attempt}/${options.retryCount})...`
      );

      await new Promise(resolve => setTimeout(resolve, options.retryDelay));

      try {
        await reconnect();
        logger.info('[ConnectionPool] Reconnected successfully, resuming task...');
      } catch (reconnectError) {
        logger.error(`[ConnectionPool] Reconnect failed: ${(reconnectError as Error).message}`);
        throw reconnectError;
      }
    }
  }

  throw new Error('[ConnectionPool] Unexpected end of retry loop');
}

/**
 * Задержка нового соединения если превышен лимит maxConnections для данного хоста.
 * Ждёт высвобождения слота через polling.
 */
export async function waitForConnectionSlot(
  host: string,
  port: number,
  maxConnections: number,
  timeoutMs = 30000,
  pollIntervalMs = 200
): Promise<void> {
  const start = Date.now();
  while (globalConnectionCounter.get(host, port) >= maxConnections) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(
        `[ConnectionPool] Timed out waiting for free connection slot to ${host}:${port} ` +
        `(max: ${maxConnections}, waited ${timeoutMs}ms)`
      );
    }
    await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
  }
  globalConnectionCounter.increment(host, port);
}

/**
 * Освобождает слот соединения после завершения задачи
 */
export function releaseConnectionSlot(host: string, port: number): void {
  globalConnectionCounter.decrement(host, port);
}

export { globalConnectionCounter };
export default {
  executeWithRetry,
  waitForConnectionSlot,
  releaseConnectionSlot,
  isRetryableError,
};
