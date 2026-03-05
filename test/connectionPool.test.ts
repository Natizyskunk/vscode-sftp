'use strict';
const { isRetryableError, executeWithRetry } = require('../src/core/remote-client/connectionPool');

describe('connectionPool.isRetryableError()', () => {
  test('ECONNRESET → retryable', () => {
    const err = new Error('read ECONNRESET');
    (err as any).code = 'ECONNRESET';
    expect(isRetryableError(err)).toBe(true);
  });

  test('ETIMEDOUT → retryable', () => {
    const err = new Error('connect ETIMEDOUT');
    (err as any).code = 'ETIMEDOUT';
    expect(isRetryableError(err)).toBe(true);
  });

  test('ECONNREFUSED → retryable', () => {
    const err = new Error('connect ECONNREFUSED');
    (err as any).code = 'ECONNREFUSED';
    expect(isRetryableError(err)).toBe(true);
  });

  test('socket hang up → retryable by message', () => {
    const err = new Error('socket hang up');
    expect(isRetryableError(err)).toBe(true);
  });

  test('Connection refused → retryable by message', () => {
    const err = new Error('Connection refused by host');
    expect(isRetryableError(err)).toBe(true);
  });

  test('ENOENT → NOT retryable', () => {
    const err = new Error('ENOENT: no such file');
    err.code = 'ENOENT';
    expect(isRetryableError(err)).toBe(false);
  });

  test('Permission denied → NOT retryable', () => {
    const err = new Error('Permission denied (publickey)');
    expect(isRetryableError(err)).toBe(false);
  });

  test('Invalid credentials → NOT retryable', () => {
    const err = new Error('All configured authentication methods failed');
    expect(isRetryableError(err)).toBe(false);
  });
});

describe('connectionPool.executeWithRetry()', () => {
  test('успешное выполнение с первой попытки', async () => {
    const result = await executeWithRetry(() => Promise.resolve(42));
    expect(result).toBe(42);
  });

  test('успешное выполнение после 1 ретрая', async () => {
    let attempts = 0;
    const result = await executeWithRetry(async () => {
      attempts++;
      if (attempts < 2) {
        const err = new Error('socket hang up');
        throw err;
      }
      return 'ok';
    }, { retryCount: 3, retryDelay: 10 });
    expect(result).toBe('ok');
    expect(attempts).toBe(2);
  });

  test('выброс ошибки после исчерпания попыток', async () => {
    const err = new Error('read ECONNRESET');
    err.code = 'ECONNRESET';
    await expect(
      executeWithRetry(() => Promise.reject(err), { retryCount: 2, retryDelay: 10 })
    ).rejects.toThrow('ECONNRESET');
  });

  test('non-retryable ошибка выбрасывается сразу', async () => {
    let attempts = 0;
    const err = new Error('Permission denied');
    await expect(
      executeWithRetry(async () => { attempts++; throw err; }, { retryCount: 3, retryDelay: 10 })
    ).rejects.toThrow('Permission denied');
    expect(attempts).toBe(1); // только 1 попытка без retry
  });
});
