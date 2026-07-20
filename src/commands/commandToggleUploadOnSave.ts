import { Uri } from 'vscode';
import { COMMAND_TOGGLE_UPLOAD_ON_SAVE } from '../constants';
import { showInformationMessage, showErrorMessage } from '../host';
import app from '../app';
import { FileService } from '../core';
import { getConfigPath, writeConfigValue } from '../modules/config';
import { checkCommand } from './abstract/createCommand';
import { resolveTargetService } from './shared';

// pick out the array element in an sftp.json that belongs to `service`, so a
// multi-config file gets the right entry flipped
function matchServiceConfig(service: FileService) {
  const raw = service.getRawConfig();
  return (config: any) =>
    config.host === raw.host &&
    (raw.name === undefined || config.name === raw.name) &&
    (raw.context === undefined || config.context === raw.context);
}

export default checkCommand({
  id: COMMAND_TOGGLE_UPLOAD_ON_SAVE,

  async handleCommand(uri?: Uri) {
    const service = await resolveTargetService(uri, 'Select a config to toggle Upload on Save');
    if (!service) {
      showErrorMessage('No SFTP config found to toggle Upload on Save.');
      return;
    }

    let current: boolean;
    try {
      current = Boolean(service.getConfig().uploadOnSave);
    } catch (error) {
      showErrorMessage(`Invalid config: ${error.message}`);
      return;
    }

    const next = !current;
    const configPath = getConfigPath(service.workspace);
    try {
      await writeConfigValue(configPath, 'uploadOnSave', next, matchServiceConfig(service));
    } catch (error) {
      showErrorMessage(`Failed to update ${configPath}: ${error.message}`);
      return;
    }

    // reflect the change immediately, without waiting for a config reload
    service.setConfigValue('uploadOnSave', next);
    app.state.uploadOnSave = next;
    showInformationMessage(`Upload on Save ${next ? 'enabled' : 'disabled'}.`);
  },
});
