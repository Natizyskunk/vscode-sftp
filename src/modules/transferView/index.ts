import * as vscode from 'vscode';
import TransferTask from '../../core/transferTask';
import TransferTreeDataProvider from './treeDataProvider';

export default class TransferView {
  private readonly _treeDataProvider: TransferTreeDataProvider;
  private readonly _view: vscode.TreeView<TransferTask>;

  constructor(context: vscode.ExtensionContext) {
    this._treeDataProvider = new TransferTreeDataProvider();

    this._view = vscode.window.createTreeView('sftpTransfers', {
      treeDataProvider: this._treeDataProvider,
    });

    context.subscriptions.push(this._view);
  }
}
