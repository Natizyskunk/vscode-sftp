import upath from './upath';
import { promptForPassword } from '../host';
import logger from '../logger';
import app from '../app';
import { ConnectionState } from '../ui/connectionStatusBar';
import { ConnectOption } from './remote-client/remoteClient';
import {
  FileSystem,
  RemoteFileSystem,
  SFTPFileSystem,
  FTPFileSystem,
} from './fs';
import localFs from './localFs';

function hashOption(opiton) {
  return Object.keys(opiton)
    .map(key => opiton[key])
    .join('');
}

class KeepAliveRemoteFs {
  private isValid: boolean = false;

  private hasConnected: boolean = false;

  private pendingPromise: Promise<RemoteFileSystem> | null;

  private fs: RemoteFileSystem;

  constructor(private readonly id: string) {}

  async getFs(
    option: ConnectOption & {
      protocol: string;
      remoteTimeOffsetInHours: number;
    }
  ): Promise<RemoteFileSystem> {
    if (this.isValid) {
      this.pendingPromise = null;
      return Promise.resolve(this.fs);
    }

    if (this.pendingPromise) {
      return this.pendingPromise;
    }

    const connectOption = Object.assign({}, option);
    let FsConstructor: typeof SFTPFileSystem | typeof FTPFileSystem;
    if (option.protocol === 'sftp') {
      connectOption.debug = function debug(str) {
        const log = str.match(/^DEBUG(?:\[SFTP\])?: (.*?): (.*?)$/);

        if (log) {
          if (log[1] === 'Parser') return;
          logger.debug(`${log[1]}: ${log[2]}`);
        } else {
          logger.debug(str);
        }
      };
      FsConstructor = SFTPFileSystem;
    } else if (option.protocol === 'ftp') {
      connectOption.debug = function debug(str) {
        // basic-ftp logs "> CMD" / "< RESPONSE" lines and masks PASS itself
        logger.debug(str.trimEnd());
      };
      FsConstructor = FTPFileSystem;
    } else {
      throw new Error(`unsupported protocol ${option.protocol}`);
    }

    this.fs = new FsConstructor(upath, {
      clientOption: connectOption,
      remoteTimeOffsetInHours: option.remoteTimeOffsetInHours,
    });
    this.fs.onDisconnected(this.invalid.bind(this));

    app.sftpBarItem.showMsg('connecting...', connectOption.connectTimeout);
    app.connectionBarItem.setState(
      this.id,
      this.hasConnected ? ConnectionState.Reconnecting : ConnectionState.Connecting
    );
    this.pendingPromise = this.fs
      .connect(connectOption, {
        askForPasswd: promptForPassword,
      })
      .then(
        () => {
          app.sftpBarItem.reset();
          this.isValid = true;
          this.hasConnected = true;
          app.connectionBarItem.setState(this.id, ConnectionState.Connected);
          return this.fs;
        },
        err => {
          this.fs.end();
          this.invalid('error');
          throw err;
        }
      );

    return this.pendingPromise;
  }

  invalid(reason: string, err?: Error) {
    if (err) {
      logger.error(`connection ${reason}: ${err.message}`);
    }
    this.pendingPromise = null;
    this.fs.end();
    this.isValid = false;
    app.connectionBarItem.setState(
      this.id,
      reason === 'error' ? ConnectionState.Error : ConnectionState.Idle
    );
  }

  end() {
    this.fs.end();
    app.connectionBarItem.clear(this.id);
  }
}

function getLocalFs() {
  return Promise.resolve(localFs);
}

const fsTable: {
  [x: string]: KeepAliveRemoteFs;
} = {};

export function createRemoteIfNoneExist(option): Promise<FileSystem> {
  if (option.protocol === 'local') {
    return getLocalFs();
  }

  const identity = hashOption(option);
  const fs = fsTable[identity];
  if (fs !== undefined) {
    return fs.getFs(option);
  }

  const fsInstance = new KeepAliveRemoteFs(identity);
  fsTable[identity] = fsInstance;
  return fsInstance.getFs(option);
}

export function removeRemoteFs(option) {
  const identity = hashOption(option);
  const fs = fsTable[identity];
  if (fs !== undefined) {
    fs.end();
    delete fsTable[identity];
  }
}
