import app from './app';
import logger from './logger';
import { showInformationMessage } from './host';

export interface ConnectIdentity {
  protocol?: string;
  host: string;
  port?: number;
  username?: string;
}

const SECRET_KEY_PREFIX = 'sftp.password.';

// "protocol://username@host:port" — identifies a remote both in secret
// storage keys and in messages shown to the user
export function connectionToken(identity: ConnectIdentity): string {
  const protocol = identity.protocol || 'sftp';
  const port = identity.port !== undefined ? identity.port : protocol === 'ftp' ? 21 : 22;
  return `${protocol}://${identity.username}@${identity.host}:${port}`;
}

function secretKey(identity: ConnectIdentity): string {
  return SECRET_KEY_PREFIX + connectionToken(identity);
}

function getSecretStorage() {
  const context = app.vscodeContext;
  return context ? context.secrets : undefined;
}

export async function getStoredPassword(identity: ConnectIdentity): Promise<string | undefined> {
  const secrets = getSecretStorage();
  if (!secrets) {
    return undefined;
  }

  try {
    return await secrets.get(secretKey(identity));
  } catch (error) {
    logger.warn(`read password for ${connectionToken(identity)} from secret storage failed: ${error.message}`);
    return undefined;
  }
}

export async function storePassword(identity: ConnectIdentity, password: string): Promise<void> {
  const secrets = getSecretStorage();
  if (!secrets) {
    throw new Error('Secret storage is unavailable.');
  }

  await secrets.store(secretKey(identity), password);
}

export async function clearStoredPassword(identity: ConnectIdentity): Promise<boolean> {
  const secrets = getSecretStorage();
  if (!secrets) {
    return false;
  }

  const key = secretKey(identity);
  const existed = (await secrets.get(key)) !== undefined;
  await secrets.delete(key);
  return existed;
}

export async function offerToRememberPassword(identity: ConnectIdentity, password: string) {
  try {
    const answer = await showInformationMessage(
      `Remember password for ${connectionToken(identity)}?`,
      'Remember password'
    );
    if (answer === 'Remember password') {
      await storePassword(identity, password);
      logger.info(`password for ${connectionToken(identity)} saved to secret storage`);
    }
  } catch (error) {
    logger.warn(`save password for ${connectionToken(identity)} failed: ${error.message}`);
  }
}
