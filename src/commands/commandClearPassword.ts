import { COMMAND_CLEAR_PASSWORD } from '../constants';
import { showInformationMessage } from '../host';
import { connectionToken, clearStoredPassword } from '../credentialStore';
import { checkCommand } from './abstract/createCommand';
import { selectRemoteConnection } from './shared';

export default checkCommand({
  id: COMMAND_CLEAR_PASSWORD,

  async handleCommand() {
    const identity = await selectRemoteConnection();
    if (!identity) {
      return;
    }

    const removed = await clearStoredPassword(identity);
    showInformationMessage(
      removed
        ? `Password for ${connectionToken(identity)} removed from secret storage.`
        : `No saved password for ${connectionToken(identity)}.`
    );
  },
});
