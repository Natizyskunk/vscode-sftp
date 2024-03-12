import CustomError from '../customError';
import * as fs from 'fs-extra';
import * as crypto from 'crypto';
import * as path from 'path';

const PASSWORDS_DIR = 'keys';
let masterPassword: string | undefined;

export interface ConnectOption {
  // common
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

    // Essayer de récupérer le mot de passe chiffré à partir du fichier
    const decryptedPassword = await this.getDecryptedPassword(connectOption.host, config);
    if (decryptedPassword) {
      var ret = this._doConnect({ ...connectOption, password: decryptedPassword }, config);
      if (ret) {
        return ret;
      }
    }

    const password = await config.askForPasswd(`[${connectOption.host}]: Enter your password`);

    //save the typed password
    if (password !== undefined) {
      await this.saveEncryptedPassword(connectOption.host, password, config);
    }

    // cancel connect
    if (password === undefined) {
      throw new CustomError(ErrorCode.CONNECT_CANCELLED, 'cancelled');
    }

    return this._doConnect({ ...connectOption, password }, config);
  }

  private async getDecryptedPassword(host: string, config: Config): Promise<string> {
    const masterPasswordInput = await this.getMasterPassword(config);
    const passwordsFile = path.join(PASSWORDS_DIR, `${host}.txt`);
    if (!await fs.pathExists(passwordsFile)) {
      return '';
    }
    const encryptedPassword = await fs.readFile(passwordsFile, 'utf8');
    return this.decryptPassword(encryptedPassword, masterPasswordInput);
  }

  public async saveEncryptedPassword(host: string, password: string, config: Config): Promise<void> {
    const masterPasswordInput = await this.getMasterPassword(config);
    const encryptedPassword = this.encryptPassword(password, masterPasswordInput);

    const passwordsFile = path.join(PASSWORDS_DIR, `${host}.txt`);
    await fs.ensureDir(PASSWORDS_DIR);
    await fs.writeFile(passwordsFile, encryptedPassword);
  }


  private encryptPassword(password: string, masterPassword: string): string {
    const cipher = crypto.createCipher('aes-256-cbc', masterPassword);
    let encryptedPassword = cipher.update(password, 'utf8', 'hex');
    encryptedPassword += cipher.final('hex');
    return encryptedPassword;
  }

  private decryptPassword(encryptedPassword: string, masterPassword: string): string {
    const decipher = crypto.createDecipher('aes-256-cbc', masterPassword);
    let decryptedPassword = decipher.update(encryptedPassword, 'hex', 'utf8');
    decryptedPassword += decipher.final('utf8');
    return decryptedPassword;
  }

  private async getMasterPassword(config: Config): Promise<string> {
    if (!masterPassword) {
      const input = await config.askForPasswd('Please enter a master password:');
      if (!input) {
      throw new Error('The master password is required.');
      }
      masterPassword = input;
    }
    return masterPassword;
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
        cb('error');
      });
  }
}
