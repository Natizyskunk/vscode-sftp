import { window } from 'vscode';
import { COMMAND_SAVE_PASSWORD } from '../constants';
import { showInformationMessage } from '../host';
import { connectionToken, storePassword } from '../credentialStore';
import { checkCommand } from './abstract/createCommand';
import { selectRemoteConnection } from './shared';

export default checkCommand({
  id: COMMAND_SAVE_PASSWORD,

  async handleCommand() {
    const identity = await selectRemoteConnection();
    if (!identity) {
      return;
    }

    const password = await window.showInputBox({
      ignoreFocusOut: true,
      password: true,
      prompt: `Enter the password for ${connectionToken(identity)}`,
    });

    // cancelled or empty
    if (!password) {
      return;
    }

    await storePassword(identity, password);
    showInformationMessage(`Password for ${connectionToken(identity)} saved to secret storage.`);
  },
});
