import * as vscode from 'vscode';
import { registerCommand } from '../../host';
import { COMMAND_DATABASE_REFRESH } from '../../constants';
import DatabaseTreeProvider from './databaseTreeProvider';

export default class DatabaseExplorer {
  private _treeDataProvider: DatabaseTreeProvider;

  constructor(context: vscode.ExtensionContext) {
    this._treeDataProvider = new DatabaseTreeProvider();

    vscode.window.createTreeView('databaseExplorer', {
      treeDataProvider: this._treeDataProvider,
      showCollapseAll: true,
    });

    registerCommand(context, COMMAND_DATABASE_REFRESH, () => this.refresh());
  }

  get treeDataProvider(): DatabaseTreeProvider {
    return this._treeDataProvider;
  }

  refresh() {
    this._treeDataProvider.refresh();
  }

  async dispose() {
    await this._treeDataProvider.dispose();
  }
}
