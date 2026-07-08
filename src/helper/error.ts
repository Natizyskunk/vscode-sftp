import * as output from '../ui/output';
import logger from '../logger';
import { showErrorMessage } from '../host';

export function describeConnectError(err: any, host: string): Error {
  const raw = err && err.message ? err.message : String(err);
  let friendly: string;

  switch (err && err.code) {
    case 'ECONNREFUSED':
      friendly = `Connection refused by ${host}. Check the host/port and that the SSH service is running.`;
      break;
    case 'ETIMEDOUT':
      friendly = `Connection to ${host} timed out. Check your network connection and the host address.`;
      break;
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      friendly = `Could not resolve host ${host}. Check the host address.`;
      break;
    case 'ECONNRESET':
      friendly = `Connection to ${host} was reset by the remote host.`;
      break;
    case 'EHOSTUNREACH':
    case 'ENETUNREACH':
      friendly = `${host} is unreachable. Check your network connection.`;
      break;
    default:
      if (err && err.level === 'client-authentication') {
        friendly = `Authentication to ${host} failed. Check your username, password, or private key.`;
      } else if (err && err.level === 'client-timeout') {
        friendly = `Connection to ${host} timed out while waiting for a response.`;
      } else if (
        typeof raw === 'string' &&
        /handshake|host key|fingerprint/i.test(raw)
      ) {
        friendly = `Failed to verify the host key for ${host}: ${raw}`;
      } else {
        friendly = `[${host}]: ${raw}`;
      }
  }

  const wrapped = new Error(friendly);
  wrapped.stack = err && err.stack ? err.stack : wrapped.stack;
  return wrapped;
}

export function reportError(err: Error | string, ctx?: string) {
  let errorString: string;
  if (err instanceof Error) {
    errorString = err.message;
    logger.error(`${err.stack}`, ctx);
  } else {
    errorString = err;
    logger.error(errorString, ctx);
  }

  showErrorMessage(errorString, 'Detail').then(result => {
    if (result === 'Detail') {
      output.show();
    }
  });
  return;
}
