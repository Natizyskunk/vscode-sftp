'use strict';
// vscode-nls MUST be configured before any other imports that use localize()
import * as nls from 'vscode-nls';
nls.config({ messageFormat: nls.MessageFormat.bundle, bundleFormat: nls.BundleFormat.standalone })();

// The module 'vscode' contains the VS Code extensibility API
import * as vscode from 'vscode';
import app from './app';
import initCommands from './initCommands';
import { reportError } from './helper';
import fileActivityMonitor from './modules/fileActivityMonitor';
import { tryLoadConfigs } from './modules/config';
import { getAllFileService, createFileService, disposeFileService } from './modules/serviceManager';
import { getWorkspaceFolders, setContextValue } from './host';
import RemoteExplorer from './modules/remoteExplorer';

async function setupWorkspaceFolder(dir) {
  const configs = await tryLoadConfigs(dir);
  configs.forEach(config => {
    createFileService(config, dir);
  });
}

function setup(workspaceFolders: vscode.WorkspaceFolder[]) {
  fileActivityMonitor.init();
  const pendingInits = workspaceFolders.map(folder => setupWorkspaceFolder(folder.uri.fsPath));

  return Promise.all(pendingInits);
}

// this method is called when your extension is activated
// your extension is activated the very first time the command is executed
export async function activate(context: vscode.ExtensionContext) {
  try {
    initCommands(context);
  } catch (error) {
    reportError(error, 'initCommands');
  }

  const workspaceFolders = getWorkspaceFolders();
  if (!workspaceFolders) {
    return;
  }

  setContextValue('enabled', true);
  app.sftpBarItem.show();
  app.state.subscribe(_ => {
    const currentText = app.sftpBarItem.getText();
    // current is showing profile
    if (currentText.startsWith('SFTP')) {
      app.sftpBarItem.reset();
    }
    if (app.remoteExplorer) {
      app.remoteExplorer.refresh();
    }
  });
  // ── Кнопка в статус-баре для быстрого открытия визуального конфигуратора
  const configBtn = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 98);
  configBtn.text = '$(settings-gear) SFTP';
  configBtn.tooltip = 'Открыть SFTP: конфиг, файловый менеджер, логи';
  configBtn.command = 'sftp.configureServer';
  configBtn.show();
  context.subscriptions.push(configBtn);

  const termBtn = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 97);
  termBtn.text = '$(terminal) SSH';
  termBtn.tooltip = 'Открыть SSH терминал';
  termBtn.command = 'sftp.openConnectInTerminal';
  termBtn.show();
  context.subscriptions.push(termBtn);

  try {
    await setup(workspaceFolders);
    app.remoteExplorer = new RemoteExplorer(context);
  } catch (error) {
    reportError(error);
  }

}

export function deactivate() {
  fileActivityMonitor.destory();
  getAllFileService().forEach(disposeFileService);
}
