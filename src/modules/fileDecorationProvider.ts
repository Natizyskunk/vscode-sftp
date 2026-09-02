import * as vscode from 'vscode';
import { syncStatusManager, SyncStatus } from './syncStatusManager';
import logger from '../logger';

export class SftpFileDecorationProvider implements vscode.FileDecorationProvider {
  private _onDidChangeFileDecorations = new vscode.EventEmitter<vscode.Uri | vscode.Uri[] | undefined>();
  readonly onDidChangeFileDecorations = this._onDidChangeFileDecorations.event;

  async provideFileDecoration(
    uri: vscode.Uri,
    token: vscode.CancellationToken
  ): Promise<vscode.FileDecoration | undefined> {
    // Only decorate local files (not remote:// scheme)
    if (uri.scheme !== 'file') {
      return undefined;
    }

    try {
      // Get status and detailed info from sync manager (with caching)
      const status = await syncStatusManager.getStatus(uri);
      
      if (!status) {
        return undefined;
      }

      // Get detailed stats for tooltip
      const detailedInfo = await syncStatusManager.getDetailedInfo(uri);
      return this.getDecorationForStatus(status, detailedInfo);
    } catch (error) {
      logger.trace('Error providing file decoration:', error.message);
      return undefined;
    }
  }

  private getDecorationForStatus(status: SyncStatus, detailedInfo?: any): any {
    // Helper to format timestamp in German format
    const formatTime = (ms?: number) => {
      if (!ms) return 'N/A';
      const date = new Date(ms);
      return date.toLocaleString('de-DE', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    };

    // Helper to format time difference in human readable way
    const formatTimeDiff = (ms: number) => {
      const seconds = Math.floor(ms / 1000);
      const minutes = Math.floor(seconds / 60);
      const hours = Math.floor(minutes / 60);
      const days = Math.floor(hours / 24);

      if (days > 0) {
        return `${days} Tag${days !== 1 ? 'e' : ''}, ${hours % 24} Std.`;
      } else if (hours > 0) {
        return `${hours} Std., ${minutes % 60} Min.`;
      } else if (minutes > 0) {
        return `${minutes} Min., ${seconds % 60} Sek.`;
      } else {
        return `${seconds} Sek.`;
      }
    };

    // Build tooltip with timestamps
    let baseTooltip = '';
    let extendedTooltip = '';
    
    if (detailedInfo) {
      const timeDiff = detailedInfo.localMtime && detailedInfo.remoteMtime 
        ? Math.abs(detailedInfo.localMtime - detailedInfo.remoteMtime) 
        : 0;
      
      extendedTooltip = `\nLokal:  ${formatTime(detailedInfo.localMtime)} (${detailedInfo.localSize || 0} Bytes)\nRemote: ${formatTime(detailedInfo.remoteMtime)} (${detailedInfo.remoteSize || 0} Bytes)`;
      if (timeDiff > 0) {
        extendedTooltip += `\nZeitdifferenz: ${formatTimeDiff(timeDiff)}`;
      }
    }

    switch (status) {
      case 'local-only':
        baseTooltip = 'Local only - not uploaded to remote';
        return {
          badge: '↑',
          tooltip: baseTooltip + extendedTooltip,
          propagate: false,
        };
      case 'remote-only':
        baseTooltip = 'Remote only - not downloaded locally';
        return {
          badge: '↓',
          tooltip: baseTooltip + extendedTooltip,
          propagate: false,
        };
      case 'modified':
        baseTooltip = 'Modified - out of sync with remote';
        return {
          badge: '!',
          tooltip: baseTooltip + extendedTooltip,
          propagate: false,
        };
      case 'synced':
        baseTooltip = 'Synced with remote';
        return {
          badge: '✓',
          tooltip: baseTooltip + extendedTooltip,
          propagate: false,
        };
      case 'ignored':
        baseTooltip = 'Ignored by ignore list';
        return {
          badge: '×',
          tooltip: baseTooltip + extendedTooltip,
          propagate: false,
        };
      default:
        return undefined;
    }
  }

  /**
   * Refresh decorations for specific file(s)
   */
  refresh(uri?: vscode.Uri | vscode.Uri[]) {
    this._onDidChangeFileDecorations.fire(uri);
  }

  /**
   * Refresh decorations after a delay (debounced)
   */
  scheduleRefresh(uri: vscode.Uri) {
    syncStatusManager.scheduleRefresh(uri);
    setTimeout(() => this.refresh(uri), 350);
  }

  /**
   * Invalidate the cache of several files and refresh them with a single event
   */
  invalidateAndRefreshMany(uris: vscode.Uri[]) {
    uris.forEach(uri => syncStatusManager.invalidate(uri));
    this.refresh(uris);
  }

  /**
   * Invalidate cache and refresh
   */
  invalidateAndRefresh(uri?: vscode.Uri) {
    if (uri) {
      syncStatusManager.invalidate(uri);
      this.refresh(uri);
    } else {
      syncStatusManager.invalidateAll();
      this.refresh();
    }
  }
}