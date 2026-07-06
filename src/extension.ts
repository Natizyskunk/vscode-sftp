'use strict';
// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import app from './app';
import initCommands from './initCommands';
import { reportError } from './helper';
import fileActivityMonitor from './modules/fileActivityMonitor';
import { tryLoadConfigs } from './modules/config';
import {
  getAllFileService,
  getFileService,
  createFileService,
  disposeFileService,
} from './modules/serviceManager';
import { getWorkspaceFolders, setContextValue } from './host';
import { isProtected } from './modules/prodGuard';
import { init as initFreshnessIndicator } from './modules/freshnessIndicator';
import RemoteExplorer from './modules/remoteExplorer';
import ChangesExplorer from './modules/changesExplorer';

async function setupWorkspaceFolder(dir) {
  const configs = await tryLoadConfigs(dir);
  configs.forEach(config => {
    createFileService(config, dir);
  });
}

function setup(workspaceFolders: readonly vscode.WorkspaceFolder[]) {
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

  // expose per-workspace storage before services are created (used to restore
  // each context's active profile)
  app.workspaceState = context.workspaceState;

  const workspaceFolders = getWorkspaceFolders();
  if (!workspaceFolders) {
    return;
  }

  setContextValue('enabled', true);
  app.sftpBarItem.show();
  const refreshUI = () => {
    const currentText = app.sftpBarItem.getText();
    // only reset when the bar is showing the idle label, not a transfer message
    if (currentText.startsWith('SFTP')) {
      app.sftpBarItem.reset();
    }
    if (app.remoteExplorer) {
      app.remoteExplorer.refresh();
    }
  };
  app.state.subscribe(refreshUI);
  // status bar follows the active editor's context (server/profile) and turns red
  // when a protected (prod) profile is active for that file
  const updateMainBar = () => {
    app.sftpBarItem.reset();
    let protectedNow = false;
    const editor = vscode.window.activeTextEditor;
    if (editor && editor.document.uri.scheme === 'file') {
      const service = getFileService(editor.document.uri);
      if (service) {
        try {
          protectedNow = isProtected(service, service.getConfig());
        } catch (e) {
          /* config not resolvable yet — treat as not protected */
        }
      }
    }
    app.sftpBarItem.setBackground(protectedNow);
  };
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(updateMainBar)
  );
  try {
    await setup(workspaceFolders);
    app.remoteExplorer = new RemoteExplorer(context);
    // tslint:disable-next-line no-unused-expression
    new ChangesExplorer(context);
    initFreshnessIndicator(context);
    updateMainBar();
  } catch (error) {
    reportError(error);
  }
}

export function deactivate() {
  fileActivityMonitor.destory();
  getAllFileService().forEach(disposeFileService);
}
