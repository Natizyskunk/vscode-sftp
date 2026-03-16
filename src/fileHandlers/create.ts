import { refreshRemoteExplorer } from './shared';
import { fileOperations,UResource } from '../core';
import createFileHandler from './createFileHandler';
import { FileHandleOption } from './option';
import logger from '../logger';
import app from '../app';
import { executeCommand } from '../host';



export const createRemoteFile = createFileHandler<FileHandleOption & { skipDir?: boolean }>({
  name: 'createRemoteFile',
  async handle(option) {
    const remoteFs = await this.fileService.getRemoteFileSystem(this.config);
    const { remoteFsPath } = this.target;

    let promise;
    promise = fileOperations.createFile(remoteFsPath, remoteFs, {});
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

export const createRemoteFolder = createFileHandler<FileHandleOption & { skipDir?: boolean }>({
  name: 'createRemoteFolder',
  async handle(option) {
    const remoteFs = await this.fileService.getRemoteFileSystem(this.config);
    const { remoteFsPath } = this.target;

    let promise;
    promise = fileOperations.createDir(remoteFsPath, remoteFs, {});
    await promise;
  },
  transformOption() {
    const config = this.config;
    return {
      ignore: config.ignore,
    };
  },
  afterHandle() {
    refreshRemoteExplorer(this.target, true);
  },
});

export const gotoFolder = createFileHandler<FileHandleOption & { skipDir?: boolean }>({
  name: 'gotoFolder',
  async handle(option) {
    let originalString = String(this.target.remoteUri);
    logger.warn(`originalString : ${originalString}`);

    const lastIndex = originalString.lastIndexOf("%2F");
    let valueAfterLast = "";
    if (lastIndex !== -1) {
      valueAfterLast = originalString.substring(lastIndex + 3);
    }
    let isDirectory = true;
    if (valueAfterLast.includes(".")) {
      isDirectory = false;
    }
    logger.warn(`isDirectory: ${isDirectory}`);
    if(isDirectory){
      await app.remoteExplorer.reveal({
        resource: UResource.makeResource(this.target.remoteUri),
        isDirectory: isDirectory,
      });
    }else{
      await executeCommand('sftp.remoteExplorer.editInLocal', this.target.localUri);
    }
  }
});
// app/etc/di.xml