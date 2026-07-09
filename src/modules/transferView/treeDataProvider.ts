import * as vscode from 'vscode';
import * as path from 'path';
import TransferTask, { TransferDirection } from '../../core/transferTask';
import { onTransferEvent } from '../serviceManager';

type TransferStatus = 'queued' | 'transferring' | 'error';

const ERROR_DISPLAY_DURATION = 5000;

export default class TransferTreeDataProvider implements vscode.TreeDataProvider<TransferTask> {
  private readonly _onDidChangeTreeData = new vscode.EventEmitter<TransferTask | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private readonly _items: Map<TransferTask, TransferStatus> = new Map();

  constructor() {
    onTransferEvent(({ type, task, error }) => {
      switch (type) {
        case 'queued':
          this._items.set(task, 'queued');
          break;
        case 'start':
          this._items.set(task, 'transferring');
          break;
        case 'done':
          if (error && !task.isCancelled()) {
            this._items.set(task, 'error');
            setTimeout(() => {
              this._items.delete(task);
              this._onDidChangeTreeData.fire(undefined);
            }, ERROR_DISPLAY_DURATION);
          } else {
            this._items.delete(task);
          }
          break;
      }

      this._onDidChangeTreeData.fire(undefined);
    });
  }

  getTreeItem(task: TransferTask): vscode.TreeItem {
    const status = this._items.get(task) || 'queued';
    const item = new vscode.TreeItem(path.basename(task.localFsPath));

    const direction = task.transferType === TransferDirection.LOCAL_TO_REMOTE ? 'uploading' : 'downloading';
    item.description = status === 'queued' ? 'queued' : status === 'error' ? 'failed' : direction;
    item.tooltip = task.localFsPath;
    item.contextValue = status === 'error' ? 'finishedTransfer' : 'activeTransfer';

    if (status === 'transferring') {
      item.iconPath = new (vscode.ThemeIcon as any)('sync~spin');
    } else if (status === 'error') {
      item.iconPath = new (vscode.ThemeIcon as any)('error');
    } else {
      item.iconPath = new (vscode.ThemeIcon as any)('clock');
    }

    return item;
  }

  getChildren(): TransferTask[] {
    return Array.from(this._items.keys()).reverse();
  }
}
