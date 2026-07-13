import logger from '../../logger';
import { getStoredPassword, offerToRememberPassword } from '../../credentialStore';
import CustomError from '../customError';

export interface ConnectOption {
  // common
  protocol?: string;
  host: string;
  port: number;
  username?: string;
  password?: string;
  connectTimeout?: number;
  debug(x: string): void;

  // ssh-only
  privateKeyPath?: string;
  privateKey?: string;
  passphrase?: string | boolean;
  interactiveAuth?: boolean | string[];
  agent?: string;
  sock?: any;
  hop?: ConnectOption | ConnectOption[];
  limitOpenFilesOnRemote?: boolean | number;

  // ftp-only
  secure?: any;
  secureOptions?: object;
  passive?: boolean;
}

export enum ErrorCode {
  CONNECT_CANCELLED,
}

export interface Config {
  askForPasswd(msg: string): Promise<string | undefined>;
}

export default abstract class RemoteClient {
  protected _client: any;
  protected _option: ConnectOption;

  constructor(option: ConnectOption) {
    this._option = option;
    this._client = this._initClient();
  }

  abstract end(): void;
  abstract getFsClient(): any;
  protected abstract _doConnect(connectOption: ConnectOption, config: Config): Promise<void>;
  protected abstract _hasProvideAuth(connectOption: ConnectOption): boolean;
  protected abstract _initClient(): any;

  async connect(connectOption: ConnectOption, config: Config) {
    if (this._hasProvideAuth(connectOption)) {
      return this._doConnect(connectOption, config);
    }

    const storedPassword = await getStoredPassword(connectOption);
    if (storedPassword !== undefined) {
      try {
        return await this._doConnect({ ...connectOption, password: storedPassword }, config);
      } catch (error) {
        logger.warn(
          `Connecting to ${connectOption.host} with the saved password failed.` +
            ' Run "SFTP: Clear Password" to remove it if it is outdated.'
        );
        throw error;
      }
    }

    const password = await config.askForPasswd(`[${connectOption.host}]: Enter your password`);

    // cancel connect
    if (password === undefined) {
      throw new CustomError(ErrorCode.CONNECT_CANCELLED, 'cancelled');
    }

    await this._doConnect({ ...connectOption, password }, config);

    // the password worked; saving it is optional so don't hold up the connection
    offerToRememberPassword(connectOption, password);
  }

  onDisconnected(cb) {
    this._client
      .on('end', () => {
        cb('end');
      })
      .on('close', () => {
        cb('close');
      })
      .on('error', err => {
        cb('error', err);
      });
  }
}
