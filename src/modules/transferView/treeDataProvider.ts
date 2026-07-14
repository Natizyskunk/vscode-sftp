import * as vscode from 'vscode';
import * as path from 'path';
import TransferTask, { TransferDirection } from '../../core/transferTask';
import { formatBytes } from '../../utils';
import { onTransferEvent } from '../serviceManager';

type TransferStatus = 'queued' | 'transferring' | 'error';

const ERROR_DISPLAY_DURATION = 5000;

export default class TransferTreeDataProvider implements vscode.TreeDataProvider<TransferTask> {
  private readonly _onDidChangeTreeData = new vscode.EventEmitter<TransferTask | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private readonly _items: Map<TransferTask, TransferStatus> = new Map();
  // pending "remove failed item" timers, so a retried task keeps its row
  private readonly _errorTimers: Map<TransferTask, ReturnType<typeof setTimeout>> = new Map();

  constructor() {
    onTransferEvent(({ type, task, error }) => {
      switch (type) {
        case 'queued':
          this._clearErrorTimer(task);
          this._items.set(task, 'queued');
          break;
        case 'start':
          this._clearErrorTimer(task);
          this._items.set(task, 'transferring');
          break;
        case 'progress':
          // only the affected row needs to re-render its description
          if (this._items.get(task) === 'transferring') {
            this._onDidChangeTreeData.fire(task);
          }
          return;
        case 'done':
          if (error && !task.isCancelled()) {
            this._items.set(task, 'error');
            const timer = setTimeout(() => {
              this._errorTimers.delete(task);
              this._items.delete(task);
              this._onDidChangeTreeData.fire(undefined);
            }, ERROR_DISPLAY_DURATION);
            this._errorTimers.set(task, timer);
          } else {
            this._items.delete(task);
          }
          break;
      }

      this._onDidChangeTreeData.fire(undefined);
    });
  }

  private _clearErrorTimer(task: TransferTask) {
    const timer = this._errorTimers.get(task);
    if (timer) {
      clearTimeout(timer);
      this._errorTimers.delete(task);
    }
  }

  private _progressDescription(task: TransferTask): string {
    const transferred = task.transferredBytes;
    const total = task.totalBytes;
    if (total && total > 0) {
      const percent = Math.min(100, Math.floor((transferred / total) * 100));
      return `${percent}% — ${formatBytes(transferred)} / ${formatBytes(total)}`;
    }
    // unknown total size: show bytes only
    return formatBytes(transferred);
  }

  getTreeItem(task: TransferTask): vscode.TreeItem {
    const status = this._items.get(task) || 'queued';
    const item = new vscode.TreeItem(path.basename(task.localFsPath));

    const direction = task.transferType === TransferDirection.LOCAL_TO_REMOTE ? 'uploading' : 'downloading';
    if (status === 'transferring') {
      item.description = task.transferredBytes > 0 ? this._progressDescription(task) : direction;
    } else if (status === 'error') {
      item.description = 'failed';
    } else {
      item.description = 'queued';
    }
    item.tooltip = task.localFsPath;
    item.contextValue = status === 'error' ? 'failedTransfer' : 'activeTransfer';

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
