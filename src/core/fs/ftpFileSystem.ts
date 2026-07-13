import { Readable, PassThrough } from 'stream';
import { Client, FileInfo, UnixPermissions } from 'basic-ftp';
import logger from '../../logger';
import { FileEntry, FileType, FileStats, FileOption } from './fileSystem';
import RemoteFileSystem from './remoteFileSystem';
import { FTPClient } from '../remote-client';

interface FtpFileHandle {
  path: string;
  flags: string;
  mode?: number;
}

const MONTHS = {
  jan: 0,
  feb: 1,
  mar: 2,
  apr: 3,
  may: 4,
  jun: 5,
  jul: 6,
  aug: 7,
  sep: 8,
  oct: 9,
  nov: 10,
  dec: 11,
};

const MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;

// Servers without MLSD support only give us the human-readable LIST date,
// e.g. "Jan  3  2020" or "Jan  3 12:30" (no year within the last ~6 months).
// Interpret it as server-local time like the old `ftp` package did, so
// remoteTimeOffsetInHours keeps correcting it the same way.
function parseRawModifiedAt(raw: string): number {
  const match = raw
    .trim()
    .match(/^([a-zA-Z]{3})\s+(\d{1,2})\s+(?:(\d{4})|(\d{1,2}):(\d{2}))$/);
  if (!match) {
    const fallback = Date.parse(raw);
    return isNaN(fallback) ? 0 : fallback;
  }

  const month = MONTHS[match[1].toLowerCase()];
  if (month === undefined) {
    return 0;
  }
  const day = parseInt(match[2], 10);

  if (match[3]) {
    return new Date(parseInt(match[3], 10), month, day).getTime();
  }

  const now = new Date();
  const date = new Date(
    now.getFullYear(),
    month,
    day,
    parseInt(match[4], 10),
    parseInt(match[5], 10)
  );
  // the year-less form is only used for recent dates, so a date in the
  // future must be from last year
  if (date.getTime() - now.getTime() > MILLISECONDS_PER_DAY) {
    date.setFullYear(date.getFullYear() - 1);
  }
  return date.getTime();
}

function getModifiedTime(info: FileInfo): number {
  // modifiedAt is only set for machine-readable listings (MLSD) and is
  // reliable; rawModifiedAt is all we get from legacy LIST output
  if (info.modifiedAt) {
    return info.modifiedAt.getTime();
  }
  return parseRawModifiedAt(info.rawModifiedAt);
}

function toNumMode(permissions?: UnixPermissions) {
  // some ftp servers don't provide permissions
  if (!permissions) return 0o666;

  return (permissions.user << 6) | (permissions.group << 3) | permissions.world;
}

function toMFMTTimestamp(date: Date): string {
  return (
    date.getUTCFullYear() +
    ('00' + (date.getUTCMonth() + 1)).slice(-2) +
    ('00' + date.getUTCDate()).slice(-2) +
    ('00' + date.getUTCHours()).slice(-2) +
    ('00' + date.getUTCMinutes()).slice(-2) +
    ('00' + date.getUTCSeconds()).slice(-2)
  );
}

export default class FTPFileSystem extends RemoteFileSystem {
  private _supportMFMT: boolean = true;

  static getFileType(info: FileInfo) {
    if (info.isDirectory) {
      return FileType.Directory;
    } else if (info.isFile) {
      return FileType.File;
    } else if (info.isSymbolicLink) {
      return FileType.SymbolicLink;
    } else {
      return FileType.Unknown;
    }
  }

  // basic-ftp's Client executes one task at a time and has no internal
  // queue (concurrent calls reject with "Client is busy"), so serialize
  // every operation on the shared control connection.
  private _taskQueue: Promise<unknown> = Promise.resolve();

  get ftp(): Client {
    return this.getClient().getFsClient();
  }

  private atomic<T>(task: () => Promise<T>): Promise<T> {
    const result = this._taskQueue.then(task, task);
    this._taskQueue = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  toFileStat(info: FileInfo): FileStats {
    const mtime = this.toLocalTime(getModifiedTime(info));
    return {
      type: FTPFileSystem.getFileType(info),
      mode: toNumMode(info.permissions), // Caution: windows will always get 0o666
      size: info.size,
      mtime,
      atime: mtime,
      target: info.link,
    };
  }

  toFileEntry(fullPath, info: FileInfo): FileEntry {
    return {
      fspath: fullPath,
      name: info.name,
      ...this.toFileStat(info),
    };
  }

  _createClient(option) {
    return new FTPClient(option);
  }

  async lstat(path: string): Promise<FileStats> {
    if (path === '/') {
      return {
        type: FileType.Directory,
        mode: 0o666,
        size: 0,
        mtime: 0,
        atime: 0,
      };
    }

    const parentPath = this.pathResolver.dirname(path);
    const nameIdentity = this.pathResolver.basename(path);
    const stats = await this.list(parentPath);

    const fileStat = stats.find(ns => ns.name === nameIdentity);

    if (!fileStat) {
      throw new Error('file not exist');
    }

    return fileStat;
  }

  open(path: string, flags: string, mode?: number): Promise<FtpFileHandle> {
    return Promise.resolve({
      path,
      flags,
      mode,
    });
  }

  close(_fd: FtpFileHandle): Promise<void> {
    return Promise.resolve();
  }

  fstat(fd: FtpFileHandle): Promise<FileStats> {
    return this.lstat(fd.path);
  }

  futimes(fd: FtpFileHandle, _atime: number, mtime: number): Promise<void> {
    if (!this._supportMFMT) return Promise.resolve();

    return this.atomicSetLastMod(fd.path, new Date(mtime * 1000)).catch(_ => {
      logger.info('Don\'t Support MFMT');
      this._supportMFMT = false;
    });
  }

  async get(path, _option?: FileOption): Promise<Readable> {
    const stream = new PassThrough();

    // resolves on the first written chunk; deliberately not 'readable',
    // which also fires on end-of-stream when a failed download closes
    // the destination without ever writing data
    const receivedData = new Promise<void>(resolve => {
      const originalWrite = stream.write.bind(stream);
      (stream as any).write = (...args: any[]) => {
        resolve();
        return originalWrite(...args);
      };
    });

    // the queue slot is held until the download completes: no other
    // command can run on the connection while a transfer is in progress
    const done = this.atomic(() => this.ftp.downloadTo(stream, path));

    try {
      // an error before any data arrived (e.g. file not found) rejects
      // get() itself instead of surfacing on the handed-off stream
      await Promise.race([receivedData, done]);
    } catch (error) {
      stream.destroy();
      throw error;
    }

    // keep a mid-transfer failure from crashing the process if the
    // consumer never attaches an 'error' listener
    stream.on('error', () => undefined);
    done.catch(error => stream.destroy(error));
    return stream;
  }

  async chmod(path: string, mode: number): Promise<void> {
    const command = `CHMOD ${mode.toString(8)} ${path}`;
    return await this.atomicSite(command);
  }

  async put(input: Readable, path, _option?: FileOption): Promise<void> {
    let inputError: Error | undefined;
    input.once('error', err => {
      inputError = err;
    });

    try {
      // basic-ftp watches the source stream and aborts the transfer itself
      // when the source errors
      await this.atomic(() => this.ftp.uploadFrom(input, path));
    } catch (error) {
      throw inputError || error;
    }
  }

  readlink(path: string): Promise<string> {
    return this.lstat(path).then(stat => stat.target!);
  }

  symlink(_targetPath: string, _path: string): Promise<void> {
    // TO-DO implement
    return Promise.resolve();
  }

  async mkdir(dir: string): Promise<void> {
    return await this.atomicMakeDir(dir);
  }

  async ensureDir(dir: string): Promise<void> {
    return await this._ensureDir(dir, true);
  }

  async _ensureDir(dir: string, checkExistFirst: boolean): Promise<void> {
    // check if exist first.
    // `ls` command can't make sure to return dotfiles, so this not work for dotfiles,
    // cause ftp don't return distinct error code for dir not exists and dir exists
    if (checkExistFirst) {
      let stat;
      try {
        stat = await this.lstat(dir);
      } catch {
        // ignore error
      }

      if (stat) {
        if (stat.type !== FileType.Directory) {
          logger.error(`${dir} (type = ${stat.type})is not a directory`);
          throw new Error(`${dir} is not a valid directory path`);
        }

        return;
      }
    }

    let err;
    try {
      await this.mkdir(dir);
      return;
    } catch (error) {
      // avoid nested code block
      err = error;
    }

    switch (err.code) {
      case 550:
        // Hooray, exists!
        if (err.message.toLowerCase().indexOf('file exists') >= 0) {
          return;
        }

        const parentPath = this.pathResolver.dirname(dir);
        // We are trying to create the root dir, something must go wrong.
        if (parentPath === dir) {
          throw err;
        }

        // If goes here, we can assume the file doesn't exist
        await this._ensureDir(parentPath, false);
        await this.mkdir(dir);
        break;

      // In the case of any other error, just see if there's a dir
      // there already.  If so, then hooray!  If not, then something
      // is borked.
      default:
        try {
          const stat = await this.lstat(dir);
          if (stat.type !== FileType.Directory) throw err;
        } catch {
          // if the stat fails, then that's super weird.
          // let the original error be the failure reason
          throw err;
        }
        break;
    }
  }

  async list(
    dir: string,
    { showHiddenFiles = false } = {}
  ): Promise<FileEntry[]> {
    const stats = await this.atomicList(dir);

    return stats
      .filter(item => item.name && item.name !== '.' && item.name !== '..')
      .map(item =>
        this.toFileEntry(this.pathResolver.join(dir, item.name), item)
      );
  }

  async unlink(path: string): Promise<void> {
    return await this.atomicDeleteFile(path);
  }

  async rmdir(path: string, recursive: boolean): Promise<void> {
    return await this.atomicRemoveDir(path, recursive);
  }

  async rename(srcPath: string, destPath: string): Promise<void> {
    return await this.renameAtomic(srcPath, destPath);
  }

  async renameAtomic(srcPath: string, destPath: string): Promise<void> {
    await this.atomic(() => this.ftp.rename(srcPath, destPath));
  }

  private atomicList(path: string): Promise<FileInfo[]> {
    return this.atomic(() => this.ftp.list(path));
  }

  private async atomicDeleteFile(path: string): Promise<void> {
    await this.atomic(() => this.ftp.remove(path));
  }

  private async atomicMakeDir(path: string): Promise<void> {
    await this.atomic(() => this.ftp.send(`MKD ${path}`));
  }

  private async atomicRemoveDir(path: string, recursive: boolean): Promise<void> {
    await this.atomic(async () => {
      if (recursive) {
        await this.ftp.removeDir(path);
      } else {
        await this.ftp.send(`RMD ${path}`);
      }
    });
  }

  private async atomicSite(command: string): Promise<void> {
    await this.atomic(() => this.ftp.send(`SITE ${command}`));
  }

  private async atomicSetLastMod(path: string, date: Date): Promise<void> {
    await this.atomic(() =>
      this.ftp.send(`MFMT ${toMFMTTimestamp(date)} ${path}`)
    );
  }
}
