import * as vscode from 'vscode';
import * as fse from 'fs-extra';
import { COMMAND_CONFIG } from '../constants';
import { newConfig, getConfigPath } from '../modules/config';
import { quickSetupConfig } from '../modules/configWizard';
import {
  getWorkspaceFolders,
  showConfirmMessage,
  showOpenDialog,
  openFolder,
  addWorkspaceFolder,
} from '../host';
import { checkCommand } from './abstract/createCommand';

async function configureWorkspace(basePath: string) {
  const exist = await fse.pathExists(getConfigPath(basePath));
  if (exist) {
    return newConfig(basePath);
  }

  const picked = await vscode.window.showQuickPick(
    [
      {
        label: 'Quick setup',
        description: 'Answer a few questions to generate the config',
      },
      {
        label: 'Edit JSON',
        description: 'Create a config file from a template and edit it',
      },
    ],
    { placeHolder: 'How do you want to set up the connection?' }
  );

  if (picked === undefined) {
    return;
  }

  if (picked.label === 'Quick setup') {
    return quickSetupConfig(basePath);
  }

  return newConfig(basePath);
}

export default checkCommand({
  id: COMMAND_CONFIG,

  async handleCommand() {
    const workspaceFolders = getWorkspaceFolders();
    if (!workspaceFolders) {
      const result = await showConfirmMessage(
        'SFTP expects to work at a folder.',
        'Open Folder',
        'Ok'
      );

      if (!result) {
        return;
      }

      return openFolder();
    }

    if (workspaceFolders.length <= 0) {
      const result = await showConfirmMessage(
        'There are no available folders in current workspace.',
        'Add Folder to Workspace',
        'Ok'
      );

      if (!result) {
        return;
      }

      const resources = await showOpenDialog({
        canSelectFiles: false,
        canSelectFolders: true,
        canSelectMany: true,
      });

      if (!resources) {
        return;
      }

      addWorkspaceFolder(...resources.map(uri => ({ uri })));
      return;
    }

    if (workspaceFolders.length === 1) {
      return configureWorkspace(workspaceFolders[0].uri.fsPath);
    }

    const initDirs = workspaceFolders.map(folder => ({
      value: folder.uri.fsPath,
      label: folder.name,
      description: folder.uri.fsPath,
    }));

    const item = await vscode.window.showQuickPick(initDirs, {
      placeHolder: 'Select a folder...',
    });

    if (item === undefined) {
      return;
    }

    return configureWorkspace(item.value);
  },
});
