import * as path from 'path';
import { Uri } from 'vscode';
import { COMMAND_ADD_TO_IGNORE } from '../constants';
import { FileType } from '../core';
import { showErrorMessage, showInformationMessage } from '../host';
import { getConfigPath, addConfigIgnoreEntry } from '../modules/config';
import { getFileService } from '../modules/serviceManager';
import { checkCommand } from './abstract/createCommand';
import { uriFromExplorerContextOrEditorContext } from './shared';

// match the sftp.json array element that produced the FileService handling this uri
function matchServiceConfig(service) {
  const raw = service.getRawConfig();
  return (config: any) =>
    config.host === raw.host &&
    (raw.name === undefined || config.name === raw.name) &&
    (raw.context === undefined || config.context === raw.context);
}

async function addToIgnore(uri: Uri) {
  const service = getFileService(uri);
  if (!service) {
    showErrorMessage(`No SFTP config found for ${uri.fsPath}.`);
    return;
  }

  let stat;
  try {
    stat = await service.getLocalFileSystem().lstat(uri.fsPath);
  } catch (error) {
    showErrorMessage(`Failed to read ${uri.fsPath}: ${error.message}`);
    return;
  }

  const relativePath = path
    .relative(service.baseDir, uri.fsPath)
    .split(path.sep)
    .join('/');
  const entry = stat.type === FileType.Directory ? `${relativePath}/**` : relativePath;

  const configPath = getConfigPath(service.workspace);
  try {
    const added = await addConfigIgnoreEntry(configPath, entry, matchServiceConfig(service));
    if (added) {
      const raw = service.getRawConfig();
      service.setConfigValue('ignore', [...(raw.ignore || []), entry]);
      showInformationMessage(`Added "${entry}" to ignore in ${configPath}.`);
    } else {
      showInformationMessage(`"${entry}" is already in ignore.`);
    }
  } catch (error) {
    showErrorMessage(`Failed to update ${configPath}: ${error.message}`);
  }
}

export default checkCommand({
  id: COMMAND_ADD_TO_IGNORE,

  async handleCommand(item, items) {
    const targets = await uriFromExplorerContextOrEditorContext(item, items);
    if (!targets) {
      return;
    }

    const targetList = Array.isArray(targets) ? targets : [targets];
    for (const uri of targetList) {
      await addToIgnore(uri);
    }
  },
});
