import * as fs from 'fs';
import { window } from 'vscode';
import { refreshRemoteExplorer } from '../shared';
import createFileHandler, { FileHandlerContext } from '../createFileHandler';
import { transfer, sync, TransferOption, SyncOption, TransferDirection } from './transfer';
import { analyzeSync, FileDiff } from '../../core/deltaSync';
import { SyncPreviewPanel } from '../../ui/syncPreviewPanel';
import logger from '../../logger';

const ONE_HOUR_MS = 60 * 60 * 1000;

/**
 * Проверяет конфликт перед выгрузкой файла.
 * Если локальный файл не редактировался > 1 часа И файл на сервере новее —
 * спрашивает пользователя: выгрузить локальный / скачать с сервера / пропустить.
 *
 * @returns 'upload' — выгрузить, 'download' — скачать с сервера, 'skip' — пропустить.
 */
async function checkUploadConflict(
  ctx: FileHandlerContext
): Promise<'upload' | 'download' | 'skip'> {
  const { localFsPath, remoteFsPath } = ctx.target;

  let localStat: fs.Stats;
  try {
    localStat = fs.statSync(localFsPath);
  } catch {
    return 'upload';
  }

  if (localStat.isDirectory()) {
    return 'upload';
  }

  const localMtimeMs = localStat.mtimeMs;
  const idleMs = Date.now() - localMtimeMs;
  const idleMin = Math.round(idleMs / 60000);

  if (idleMs < ONE_HOUR_MS) {
    return 'upload';
  }

  logger.info(`[conflict-check] ${localFsPath} не редактировался ${idleMin} мин — проверяем сервер...`);

  try {
    const remoteFs = await ctx.fileService.getRemoteFileSystem(ctx.config);
    const remoteStat = await remoteFs.lstat(remoteFsPath);
    const remoteMtimeMs = remoteStat.mtime;

    if (remoteMtimeMs <= localMtimeMs) {
      logger.info(`[conflict-check] Сервер не новее локального — выгружаем без вопросов`);
      return 'upload';
    }

    const localDate = new Date(localMtimeMs).toLocaleString();
    const remoteDate = new Date(remoteMtimeMs).toLocaleString();
    const diffSec = Math.round((remoteMtimeMs - localMtimeMs) / 1000);

    logger.warn(
      `[conflict-check] КОНФЛИКТ: ${localFsPath}\n` +
      `  Локальный: ${localDate}\n` +
      `  Сервер:    ${remoteDate} (новее на ${diffSec} сек)\n` +
      `  Ожидаем ответа пользователя...`
    );

    const choice = await window.showWarningMessage(
      `Файл на сервере новее локального:\n` +
      `  Локальный:  ${localDate}\n` +
      `  Сервер:     ${remoteDate}\n\n` +
      `Что сделать с «${remoteFsPath}»?`,
      { modal: true },
      'Выгрузить локальный',
      'Скачать с сервера',
      'Пропустить'
    );

    if (choice === 'Выгрузить локальный') {
      logger.info(`[conflict-check] Пользователь выбрал: выгрузить локальный → ${remoteFsPath}`);
      return 'upload';
    }
    if (choice === 'Скачать с сервера') {
      logger.info(`[conflict-check] Пользователь выбрал: скачать с сервера → ${localFsPath}`);
      return 'download';
    }
    logger.info(`[conflict-check] Пользователь выбрал: пропустить — ${localFsPath}`);
    return 'skip';
  } catch (err) {
    logger.warn(`[conflict-check] Не удалось получить stat сервера для ${remoteFsPath}: ${err.message} — выгружаем`);
    return 'upload';
  }
}

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
  async handle(option) {
    // Проверяем конфликт только для одиночных файлов
    const conflict = await checkUploadConflict(this);
    if (conflict === 'skip') {
      return;
    }
    if (conflict === 'download') {
      // Скачиваем файл с сервера
      const remoteFs = await this.fileService.getRemoteFileSystem(this.config);
      const localFs = this.fileService.getLocalFileSystem();
      const { localFsPath, remoteFsPath } = this.target;
      const scheduler = this.fileService.createTransferScheduler(this.config.concurrency);
      await transfer(
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
      return;
    }
    // conflict === 'upload' — стандартная выгрузка
    return uploadHandle.call(this, option);
  },
  transformOption() {
    const config = this.config;
    return {
      perserveTargetMode: config.protocol === 'sftp' && !config.filePerm,
      useTempFile: config.useTempFile,
      openSsh: config.openSsh,
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
