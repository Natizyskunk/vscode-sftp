import * as vscode from 'vscode';
import * as path from 'path';
import logger from '../logger';
import app from '../app';
import { onDidOpenTextDocument, onDidSaveTextDocument, showConfirmMessage } from '../host';
import { readConfigsFromFile } from './config';
import {
  createFileService,
  getFileService,
  findAllFileService,
  disposeFileService,
} from './serviceManager';
import { reportError, isValidFile, isConfigFile, isInWorksapce, simplifyPath } from '../helper';
import { downloadFile, uploadFile } from '../fileHandlers';

let workspaceWatcher: vscode.Disposable;

async function handleConfigSave(uri: vscode.Uri) {
  const workspaceFolder = vscode.workspace.getWorkspaceFolder(uri);
  const workspacePath = workspaceFolder.uri.fsPath;

  // dispose old service
  findAllFileService(service => service.workspace === workspacePath).forEach(disposeFileService);

  // create new service
  try {
    const configs = await readConfigsFromFile(uri.fsPath, workspacePath);
    configs.forEach(config => createFileService(workspacePath, config));
  } catch (error) {
    reportError(error);
  } finally {
    app.remoteExplorer.refresh();
  }
}

async function handleFileSave(uri: vscode.Uri) {
  const fileService = getFileService(uri);
  if (!fileService) {
    logger.error(new Error(`FileService Not Found. (${uri.toString(true)}) `));
    return;
  }

  const config = fileService.getConfig();
  if (config.uploadOnSave) {
    const fspath = uri.fsPath;
    logger.info(`[file-save] ${fspath}`);
    try {
      app.sftpBarItem.showMsg(`upload ${path.basename(fspath)}`, simplifyPath(fspath));
      await uploadFile(uri);
      app.sftpBarItem.showMsg(`done`, 2 * 1000);
    } catch (error) {
      logger.error(error, `upload ${fspath}`);
      app.sftpBarItem.showMsg('fail', 4 * 1000);
    }
  }
}

async function downloadOnOpen(uri: vscode.Uri) {
  const fileService = getFileService(uri);
  if (!fileService && /* a new-created config */ !isConfigFile(uri)) {
    logger.error(new Error(`FileService Not Found. (${uri.toString(true)}) `));
    return;
  }

  const config = fileService.getConfig();
  if (config.downloadOnOpen) {
    if (config.downloadOnOpen === 'confirm') {
      const isConfirm = await showConfirmMessage('Do you want SFTP to download this file?');
      if (!isConfirm) return;
    }

    const fspath = uri.fsPath;
    logger.info(`[file-open] ${fspath}`);
    try {
      app.sftpBarItem.showMsg(`download ${path.basename(fspath)}`, simplifyPath(fspath));
      await downloadFile(uri);
      app.sftpBarItem.showMsg(`done`, 2 * 1000);
    } catch (error) {
      logger.error(error, `download ${fspath}`);
      app.sftpBarItem.showMsg('fail', 4 * 1000);
    }
  }
}

function watchWorkspace({
  onDidSaveFile,
  onDidSaveSftpConfig,
}: {
  onDidSaveFile: (uri: vscode.Uri) => void;
  onDidSaveSftpConfig: (uri: vscode.Uri) => void;
}) {
  if (workspaceWatcher) {
    workspaceWatcher.dispose();
  }

  workspaceWatcher = onDidSaveTextDocument((doc: vscode.TextDocument) => {
    const uri = doc.uri;
    if (!isValidFile(uri) || !isInWorksapce(uri.fsPath)) {
      return;
    }

    // remove staled cache
    if (app.ignoreFileCache.has(uri.fsPath)) {
      app.ignoreFileCache.del(uri.fsPath);
    }

    if (isConfigFile(uri)) {
      onDidSaveSftpConfig(uri);
      return;
    }

    onDidSaveFile(uri);
  });
}

function init() {
  onDidOpenTextDocument((doc: vscode.TextDocument) => {
    if (!isValidFile(doc.uri) || !isInWorksapce(doc.uri.fsPath)) {
      return;
    }

    downloadOnOpen(doc.uri);
  });

  watchWorkspace({
    onDidSaveFile: handleFileSave,
    onDidSaveSftpConfig: handleConfigSave,
  });
}

function destory() {
  if (workspaceWatcher) {
    workspaceWatcher.dispose();
  }
}

export default {
  init,
  destory,
};
