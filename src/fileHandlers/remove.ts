import { refreshRemoteExplorer } from './shared';
import { fileOperations, FileType } from '../core';
import createFileHandler from './createFileHandler';
import { FileHandleOption } from './option';
import logger from '../logger';

export const removeRemote = createFileHandler<FileHandleOption & { skipDir?: boolean }>({
  name: 'removeRemote',
  async handle(option) {
    const remoteFs = await this.fileService.getRemoteFileSystem(this.config);
    const { remoteFsPath } = this.target;
    const stat = await remoteFs.lstat(remoteFsPath);
    let promise;
    switch (stat.type) {
      case FileType.Directory:
        if (option.skipDir) {
          return;
        }

        promise = fileOperations.removeDir(remoteFsPath, remoteFs, {});
        break;
      case FileType.File:
      case FileType.SymbolicLink:
        promise = fileOperations.removeFile(remoteFsPath, remoteFs, {});
        break;
      default:
        logger.warn(`Unsupported file type (type = ${stat.type}). File ${remoteFsPath}`);
    }
    await promise;
  },
  transformOption() {
    const config = this.config;
    return {
      ignore: config.ignore,
    };
  },
  afterHandle() {
    refreshRemoteExplorer(this.target, false);
  },
});

export const removeBoth = createFileHandler<FileHandleOption & { skipDir?: boolean }>({
  name: 'removeBoth',
  async handle(option) {
    const vscode = require('vscode');
    const remoteFs = await this.fileService.getRemoteFileSystem(this.config);
    const { remoteFsPath, localFsPath } = this.target;

    // 1. Удаляем на сервере
    try {
      const stat = await remoteFs.lstat(remoteFsPath);
      switch (stat.type) {
        case FileType.Directory:
          await fileOperations.removeDir(remoteFsPath, remoteFs, {});
          break;
        case FileType.File:
        case FileType.SymbolicLink:
          await fileOperations.removeFile(remoteFsPath, remoteFs, {});
          break;
        default:
          logger.warn(`Unsupported file type (type = ${stat.type}). File ${remoteFsPath}`);
      }
    } catch (err) {
      logger.warn(`Remote delete failed (may not exist): ${remoteFsPath} — ${err.message}`);
    }

    // 2. Удаляем локально через VS Code (корзина)
    await vscode.workspace.fs.delete(vscode.Uri.file(localFsPath), { recursive: true, useTrash: true });
  },
  transformOption() {
    const config = this.config;
    return {
      ignore: config.ignore,
    };
  },
  afterHandle() {
    refreshRemoteExplorer(this.target, false);
  },
});
