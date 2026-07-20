import { Uri } from 'vscode';
import { COMMAND_TEST_CONNECTION } from '../constants';
import { showInformationMessage, showErrorMessage } from '../host';
import logger from '../logger';
import { checkCommand } from './abstract/createCommand';
import { resolveTargetService } from './shared';

export default checkCommand({
  id: COMMAND_TEST_CONNECTION,

  async handleCommand(uri?: Uri) {
    const service = await resolveTargetService(uri, 'Select a config to test');
    if (!service) {
      showErrorMessage('No SFTP config found to test.');
      return;
    }

    let config;
    try {
      config = service.getConfig();
    } catch (error) {
      showErrorMessage(`Invalid config: ${error.message}`);
      return;
    }

    if (config.protocol === 'local') {
      showInformationMessage('Active profile uses the local protocol; no connection needed.');
      return;
    }

    try {
      const fs = await service.getRemoteFileSystem(config);
      await fs.lstat('/');
      showInformationMessage(
        `Successfully connected to ${config.host}:${config.port} via ${config.protocol.toUpperCase()}.`
      );
    } catch (error) {
      logger.error(error, 'testConnection');
      showErrorMessage(`Failed to connect to ${config.host}:${config.port}: ${error.message}`);
    }
  },
});
