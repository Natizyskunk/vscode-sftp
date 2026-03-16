export class OperationTimeoutError extends Error {
  constructor(operationName: string, timeoutMs: number) {
    super(`Operation "${operationName}" timed out after ${timeoutMs}ms`);
    this.name = 'OperationTimeoutError';
  }
}

export function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operationName: string
): Promise<T> {
  if (!timeoutMs || timeoutMs <= 0) {
    return promise;
  }

  let timer: any;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new OperationTimeoutError(operationName, timeoutMs)),
      timeoutMs
    );
  });
  return Promise.race([promise, timeoutPromise]).then(
    result => {
      clearTimeout(timer);
      return result;
    },
    err => {
      clearTimeout(timer);
      throw err;
    }
  );
}
