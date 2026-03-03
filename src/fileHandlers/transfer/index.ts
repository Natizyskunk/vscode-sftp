import { refreshRemoteExplorer } from '../shared';
import createFileHandler, { FileHandlerContext } from '../createFileHandler';
import { transfer, sync, TransferOption, SyncOption, TransferDirection } from './transfer';
import { analyzeSync, FileDiff } from '../../core/deltaSync';
import { SyncPreviewPanel } from '../../ui/syncPreviewPanel';

function createTransferHandle(direction: TransferDirection) {
  return async function handle(this: FileHandlerContext, option) {
    const remoteFs = await this.fileService.getRemoteFileSystem(this.config);
    const localFs = this.fileService.getLocalFileSystem();
    const { localFsPath, remoteFsPath } = this.target;
    const scheduler = this.fileService.createTransferScheduler(this.config.concurrency);
    let transferConfig;

    if (direction === TransferDirection.REMOTE_TO_LOCAL) {
      transferConfig = {
        srcFsPath: remoteFsPath,
        srcFs: remoteFs,
        targetFsPath: localFsPath,
        targetFs: localFs,
        transferOption: option,
        transferDirection: TransferDirection.REMOTE_TO_LOCAL,
      };
    } else {
      transferConfig = {
        srcFsPath: localFsPath,
        srcFs: localFs,
        targetFsPath: remoteFsPath,
        targetFs: remoteFs,
        transferOption: option,
        filePerm: this.config.filePerm,
        dirPerm: this.config.dirPerm,
        transferDirection: TransferDirection.LOCAL_TO_REMOTE,
      };
    }
    // todo: abort at here. we should stop collect task
    await transfer(transferConfig, t => scheduler.add(t));
    await scheduler.run();
  };
}

const uploadHandle = createTransferHandle(TransferDirection.LOCAL_TO_REMOTE);
const downloadHandle = createTransferHandle(TransferDirection.REMOTE_TO_LOCAL);

export const sync2Remote = createFileHandler<SyncOption>({
  name: 'sync local ➞ remote',
  async handle(option) {
    const remoteFs = await this.fileService.getRemoteFileSystem(this.config);
    const localFs = this.fileService.getLocalFileSystem();
    const { localFsPath, remoteFsPath } = this.target;
    const scheduler = this.fileService.createTransferScheduler(this.config.concurrency);
    // Attach filePerm and dirPerm to transferOption
    option.filePerm = this.config.filePerm;
    option.dirPerm = this.config.dirPerm;

    const syncOpt = this.config.syncOption || {};

    if (syncOpt.smartSync) {
      // ---- Smart Sync: analyze, show preview, then sync only changed files ----
      const diffs = await analyzeSync(
        localFs,
        remoteFs,
        localFsPath,
        remoteFsPath,
        {
          conflictResolution: syncOpt.conflictResolution || 'newer',
          mtimeDeltaSeconds: syncOpt.mtimeDeltaSeconds || 2,
          ignore: option.ignore ? (p: string) => (option.ignore as any)(p) : null,
        }
      );

      const uploadsOnly = diffs.filter(d => d.action === 'upload');
      if (uploadsOnly.length === 0) {
        const vscode = require('vscode');
        vscode.window.showInformationMessage('SFTP: Все файлы актуальны — синхронизация не требуется');
        return;
      }

      await new Promise<void>(resolve => {
        SyncPreviewPanel.show(uploadsOnly, async (confirmed: FileDiff[]) => {
          for (const diff of confirmed) {
            await sync(
              {
                srcFsPath: diff.localPath,
                srcFs: localFs,
                targetFsPath: diff.remotePath,
                targetFs: remoteFs,
                transferOption: option,
                transferDirection: TransferDirection.LOCAL_TO_REMOTE,
              },
              t => scheduler.add(t)
            );
          }
          await scheduler.run();
          resolve();
        });
      });
    } else {
      // ---- Standard sync (original behavior) ----
      await sync(
        {
          srcFsPath: localFsPath,
          srcFs: localFs,
          targetFsPath: remoteFsPath,
          targetFs: remoteFs,
          transferOption: option,
          transferDirection: TransferDirection.LOCAL_TO_REMOTE,
        },
        t => scheduler.add(t)
      );
      await scheduler.run();
    }
  },
  transformOption() {
    const config = this.config;
    const syncOption = config.syncOption || {};
    return {
      perserveTargetMode: config.protocol === 'sftp' && !config.filePerm && !config.dirPerm,
      useTempFile: config.useTempFile,
      openSsh: config.openSsh,
      ignore: config.ignore,
      delete: syncOption.delete,
      skipCreate: syncOption.skipCreate,
      ignoreExisting: syncOption.ignoreExisting,
      update: syncOption.update,
    };
  },
  afterHandle() {
    refreshRemoteExplorer(this.target, true);
  },
});

export const sync2Local = createFileHandler<SyncOption>({
  name: 'sync remote ➞ local',
  async handle(option) {
    const remoteFs = await this.fileService.getRemoteFileSystem(this.config);
    const localFs = this.fileService.getLocalFileSystem();
    const { localFsPath, remoteFsPath } = this.target;
    const scheduler = this.fileService.createTransferScheduler(this.config.concurrency);
    const syncOpt = this.config.syncOption || {};

    if (syncOpt.smartSync) {
      // ---- Smart Sync: analyze diffs, show preview ----
      const diffs = await analyzeSync(
        localFs,
        remoteFs,
        localFsPath,
        remoteFsPath,
        {
          conflictResolution: syncOpt.conflictResolution || 'newer',
          mtimeDeltaSeconds: syncOpt.mtimeDeltaSeconds || 2,
          ignore: option.ignore ? (p: string) => (option.ignore as any)(p) : null,
        }
      );

      const downloadsOnly = diffs.filter(d => d.action === 'download');
      if (downloadsOnly.length === 0) {
        const vscode = require('vscode');
        vscode.window.showInformationMessage('SFTP: Все файлы актуальны — синхронизация не требуется');
        return;
      }

      await new Promise<void>(resolve => {
        SyncPreviewPanel.show(downloadsOnly, async (confirmed: FileDiff[]) => {
          for (const diff of confirmed) {
            await sync(
              {
                srcFsPath: diff.remotePath,
                srcFs: remoteFs,
                targetFsPath: diff.localPath,
                targetFs: localFs,
                transferOption: option,
                transferDirection: TransferDirection.REMOTE_TO_LOCAL,
              },
              t => scheduler.add(t)
            );
          }
          await scheduler.run();
          resolve();
        });
      });
    } else {
      // ---- Standard sync ----
      await sync(
        {
          srcFsPath: remoteFsPath,
          srcFs: remoteFs,
          targetFsPath: localFsPath,
          targetFs: localFs,
          transferOption: option,
          transferDirection: TransferDirection.REMOTE_TO_LOCAL,
        },
        t => scheduler.add(t)
      );
      await scheduler.run();
    }
  },
  transformOption() {
    const config = this.config;
    const syncOption = config.syncOption || {};
    return {
      perserveTargetMode: false,
      ignore: config.ignore,
      delete: syncOption.delete,
      skipCreate: syncOption.skipCreate,
      ignoreExisting: syncOption.ignoreExisting,
      update: syncOption.update,
    };
  },
});

export const upload = createFileHandler<TransferOption>({
  name: 'upload',
  handle: uploadHandle,
  transformOption() {
    const config = this.config;
    return {
      perserveTargetMode: config.protocol === 'sftp' && !config.filePerm && !config.dirPerm,
      useTempFile: config.useTempFile,
      openSsh: config.openSsh,
      // remoteTimeOffsetInHours: config.remoteTimeOffsetInHours,
      ignore: config.ignore,
    };
  },
  afterHandle() {
    refreshRemoteExplorer(this.target, this.fileService);
  },
});

export const uploadFile = createFileHandler<TransferOption>({
  name: 'upload file',
  handle: uploadHandle,
  transformOption() {
    const config = this.config;
    return {
      perserveTargetMode: config.protocol === 'sftp' && !config.filePerm,
      useTempFile: config.useTempFile,
      openSsh: config.openSsh,
      // remoteTimeOffsetInHours: config.remoteTimeOffsetInHours,
      ignore: config.ignore,
    };
  },
  afterHandle() {
    refreshRemoteExplorer(this.target, false);
  },
});

export const uploadFolder = createFileHandler<TransferOption>({
  name: 'upload folder',
  handle: uploadHandle,
  transformOption() {
    const config = this.config;
    return {
      perserveTargetMode: config.protocol === 'sftp' && !config.dirPerm,
      useTempFile: config.useTempFile,
      openSsh: config.openSsh,
      // remoteTimeOffsetInHours: config.remoteTimeOffsetInHours,
      ignore: config.ignore,
    };
  },
  afterHandle() {
    refreshRemoteExplorer(this.target, true);
  },
});

export const download = createFileHandler<TransferOption>({
  name: 'download',
  handle: downloadHandle,
  transformOption() {
    const config = this.config;
    return {
      perserveTargetMode: false,
      // remoteTimeOffsetInHours: config.remoteTimeOffsetInHours,
      ignore: config.ignore,
    };
  },
});

export const downloadFile = createFileHandler<TransferOption>({
  name: 'download file',
  handle: downloadHandle,
  transformOption() {
    const config = this.config;
    return {
      perserveTargetMode: false,
      // remoteTimeOffsetInHours: config.remoteTimeOffsetInHours,
      ignore: config.ignore,
    };
  },
});

export const downloadFolder = createFileHandler<TransferOption>({
  name: 'download folder',
  handle: downloadHandle,
  transformOption() {
    const config = this.config;
    return {
      perserveTargetMode: false,
      // remoteTimeOffsetInHours: config.remoteTimeOffsetInHours,
      ignore: config.ignore,
    };
  },
});
