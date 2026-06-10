import { COMMAND_DELETE_LOCAL_AND_REMOTE } from '../constants';
import { checkFileCommand } from './abstract/createCommand';
import fileCommandDeleteLocalAndRemoteActiveFile from './fileCommandDeleteLocalAndRemoteActiveFile';
import { uriFromExplorerContextOrEditorContext } from './shared';
import { showConfirmMessage } from '../host';

export default checkFileCommand({
  ...fileCommandDeleteLocalAndRemoteActiveFile,
  id: COMMAND_DELETE_LOCAL_AND_REMOTE,
  async getFileTarget(item, items) {
    const targets = await uriFromExplorerContextOrEditorContext(item, items);

    if (!targets) {
      return;
    }

    const result = await showConfirmMessage(
      'Are you sure you want to delete both local and remote copies of this file?',
      'Delete',
      'Cancel',
      true
    );

    return result ? targets : undefined;
  },
});
