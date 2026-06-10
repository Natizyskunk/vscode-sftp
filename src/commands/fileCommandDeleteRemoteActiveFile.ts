import { COMMAND_DELETE_REMOTE_ACTIVEFILE } from '../constants';
import { checkFileCommand } from './abstract/createCommand';
import fileCommandDeleteRemote from './fileCommandDeleteRemote';
import { getActiveDocumentUri } from './shared';
import { showConfirmMessage } from '../host';

export default checkFileCommand({
  ...fileCommandDeleteRemote,
  id: COMMAND_DELETE_REMOTE_ACTIVEFILE,
  async getFileTarget() {
    const target = await getActiveDocumentUri();

    if (!target) {
      return;
    }

    const result = await showConfirmMessage(
      'Are you sure you want to delete the remote copy of this file?',
      'Delete',
      'Cancel',
      true
    );

    return result ? target : undefined;
  },
});
