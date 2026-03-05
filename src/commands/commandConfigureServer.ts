import * as path from 'path';
import * as vscode from 'vscode';
import { ServerConfigPanel } from '../ui/serverConfigPanel';
import { checkCommand } from './abstract/createCommand';
import { COMMAND_CONFIGURE_SERVER } from '../constants';

export default checkCommand({
  id: COMMAND_CONFIGURE_SERVER,

  async handleCommand() {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
      vscode.window.showErrorMessage('SFTP: Откройте папку проекта');
      return;
    }

    let workspaceRoot: string;
    if (folders.length === 1) {
      workspaceRoot = folders[0].uri.fsPath;
    } else {
      const pick = await vscode.window.showQuickPick(
        folders.map(f => ({ label: f.name, detail: f.uri.fsPath, fsPath: f.uri.fsPath })),
        { placeHolder: 'Выберите папку проекта' }
      );
      if (!pick) return;
      workspaceRoot = pick.fsPath;
    }

    const configPath = path.join(workspaceRoot, '.vscode', 'sftp.json');
    ServerConfigPanel.createOrShow(configPath);
  },
});

