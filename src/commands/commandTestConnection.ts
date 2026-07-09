import * as path from 'path';
import { Uri, window } from 'vscode';
import { COMMAND_TEST_CONNECTION } from '../constants';
import { showInformationMessage, showErrorMessage } from '../host';
import logger from '../logger';
import { getAllFileService } from '../modules/serviceManager';
import { checkCommand } from './abstract/createCommand';

function normalizePath(p: string) {
  return path.normalize(p);
}

function findFileServiceForConfigUri(uri: Uri) {
  const configDir = normalizePath(path.dirname(path.dirname(uri.fsPath)));
  return getAllFileService().find(service => normalizePath(service.workspace) === configDir);
}

export default checkCommand({
  id: COMMAND_TEST_CONNECTION,

  async handleCommand(uri?: Uri) {
    const targetUri = uri || (window.activeTextEditor && window.activeTextEditor.document.uri);
    if (!targetUri) {
      showErrorMessage('No sftp.json file found to test.');
      return;
    }

    const service = findFileServiceForConfigUri(targetUri);
    if (!service) {
      showErrorMessage('Could not find a matching SFTP config for this file.');
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
