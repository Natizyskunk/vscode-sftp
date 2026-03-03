import * as vscode from 'vscode';
import * as path from 'path';
import { ServerConfigPanel } from '../ui/serverConfigPanel';

/**
 * sftp.configureServer — открывает визуальный конфигуратор SFTP.
 */
export default {
  id: 'sftp.configureServer',
  run() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
      vscode.window.showErrorMessage('SFTP: Откройте папку проекта');
      return;
    }
    const workspaceRoot = workspaceFolders[0].uri.fsPath;
    const configPath = path.join(workspaceRoot, '.vscode', 'sftp.json');
    ServerConfigPanel.createOrShow(configPath);
  },
};
