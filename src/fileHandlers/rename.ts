import { fileOperations } from '../core';
import createFileHandler from './createFileHandler';

// Rename a remote file to the remote path of the target uri.
// "originPath" is the current remote path of the file.
export const renameRemote = createFileHandler<{ originPath: string }>({
  name: 'rename',
  async handle({ originPath }) {
    const remoteFs = await this.fileService.getRemoteFileSystem(this.config);
    const { remoteFsPath } = this.target;
    await fileOperations.rename(originPath, remoteFsPath, remoteFs);
  },
});
