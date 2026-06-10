import { COMMAND_DELETE_LOCAL_AND_REMOTE_ACTIVEFILE } from '../constants';
import { removeRemote } from '../fileHandlers';
import { checkFileCommand } from './abstract/createCommand';
import { getActiveDocumentUri } from './shared';
import { showConfirmMessage } from '../host';

function isRemoteFileNotFound(error: any): boolean {
  if (!error) {
    return false;
  }

  const code = error.code;
  const message = String(error.message || '').toLowerCase();

  if (code === 'ENOENT' || code === 2) {
    return true;
  }

  if (message.includes('file not exist') || message.includes('no such file') || message.includes('not found')) {
    return true;
  }

  return false;
}

export default checkFileCommand({
  id: COMMAND_DELETE_LOCAL_AND_REMOTE_ACTIVEFILE,
  async getFileTarget() {
    const target = await getActiveDocumentUri();

    if (!target) {
      return;
    }

    const result = await showConfirmMessage(
      'Are you sure you want to delete both local and remote copies of this file?',
      'Delete',
      'Cancel',
      true
    );

    return result ? target : undefined;
  },

  async handleFile(ctx) {
    let remoteDeleted = false;

    try {
      await removeRemote(ctx);
      remoteDeleted = true;
    } catch (error) {
      const continueMessage = isRemoteFileNotFound(error)
        ? 'The remote file could not be found, continue deleting local file?'
        : 'The remote file could not be deleted, continue deleting local file?';
      const continueDelete = await showConfirmMessage(continueMessage, 'Continue', 'Cancel', true);

      if (!continueDelete) {
        return;
      }
    }

    await ctx.fileService.getLocalFileSystem().unlink(ctx.target.localFsPath);

    if (remoteDeleted) {
      return;
    }
  },
});
