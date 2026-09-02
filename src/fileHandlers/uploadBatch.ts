import { Uri, CancellationToken } from 'vscode';
import { FileService, FileType, TransferTask, UResource } from '../core';
import { handleCtxFromUri } from './createFileHandler';
import { transfer, TransferDirection } from './transfer/transfer';
import { refreshRemoteExplorer } from './shared';
import app from '../app';
import logger from '../logger';

export interface BatchItem {
  uri: Uri;
}

export interface BatchOutcome<T> {
  item: T;
  status: 'done' | 'failed' | 'cancelled';
  error?: any;
  // number of files actually transferred (0 for ignored files or empty folders)
  transferred: number;
}

export interface BatchHooks {
  token?: CancellationToken;
  onTaskDone?: (task: TransferTask, error: Error | null, done: number, total: number) => void;
}

interface Entry<T> {
  item: T;
  target: UResource;
  isDirectory: boolean;
}

// Upload many local files/folders of one file service with a single transfer scheduler.
// Compared to calling the "upload" handler per file this creates every remote folder only once,
// keeps the connection busy with transfers only and refreshes explorer/decorations once at the end.
export async function uploadBatch<T extends BatchItem>(
  fileService: FileService,
  items: T[],
  hooks: BatchHooks = {}
): Promise<BatchOutcome<T>[]> {
  const config = fileService.getConfig();
  const remoteFs = await fileService.getRemoteFileSystem(config);
  const localFs = fileService.getLocalFileSystem();
  const token = hooks.token;
  const isCancelled = () => !!token && token.isCancellationRequested;

  const outcomes = new Map<T, BatchOutcome<T>>();
  items.forEach(item => outcomes.set(item, { item, status: 'done', transferred: 0 }));
  const fail = (item: T, error: any) => {
    const outcome = outcomes.get(item)!;
    if (outcome.status !== 'failed') {
      outcome.status = 'failed';
      outcome.error = error;
    }
  };

  const transferOption = {
    perserveTargetMode: config.protocol === 'sftp' && !config.filePerm && !config.dirPerm,
    useTempFile: config.useTempFile,
    openSsh: config.openSsh,
    ignore: config.useIgnoreForUpload ? config.ignore : null,
  };

  // resolve remote targets and local file types
  const entries: Entry<T>[] = [];
  for (const item of items) {
    try {
      const { target } = handleCtxFromUri(item.uri);
      const stat = await localFs.lstat(target.localFsPath);
      entries.push({ item, target, isDirectory: stat.type === FileType.Directory });
    } catch (error) {
      fail(item, error);
    }
  }

  // create the remote folders once instead of once per file
  const remoteDirs: string[] = [];
  entries
    .filter(entry => !entry.isDirectory)
    .forEach(entry => {
      const dir = remoteFs.pathResolver.dirname(entry.target.remoteFsPath);
      if (remoteDirs.indexOf(dir) === -1) {
        remoteDirs.push(dir);
      }
    });
  remoteDirs.sort((left, right) => left.length - right.length);

  const failedDirs: { [dir: string]: any } = {};
  for (const dir of remoteDirs) {
    if (isCancelled()) {
      break;
    }
    try {
      await remoteFs.ensureDir(dir);
      if (config.dirPerm) {
        await remoteFs.chmod(dir, parseInt(String(config.dirPerm), 8));
      }
    } catch (error) {
      failedDirs[dir] = error;
      logger.error(error, `ensure remote folder ${dir}`);
    }
  }

  // collect all transfer tasks in one scheduler
  const scheduler = fileService.createTransferScheduler(config.concurrency);
  const owners = new Map<TransferTask, T>();
  const expectedTasks = new Map<T, number>();
  const completedTasks = new Map<T, number>();
  for (const entry of entries) {
    if (outcomes.get(entry.item)!.status === 'failed') {
      continue;
    }
    if (isCancelled()) {
      outcomes.get(entry.item)!.status = 'cancelled';
      continue;
    }

    const dir = remoteFs.pathResolver.dirname(entry.target.remoteFsPath);
    if (!entry.isDirectory && failedDirs[dir]) {
      fail(entry.item, failedDirs[dir]);
      continue;
    }

    try {
      await transfer(
        {
          srcFsPath: entry.target.localFsPath,
          srcFs: localFs,
          targetFsPath: entry.target.remoteFsPath,
          targetFs: remoteFs,
          transferOption,
          filePerm: config.filePerm,
          dirPerm: config.dirPerm,
          transferDirection: TransferDirection.LOCAL_TO_REMOTE,
          ensureDirExist: false,
        },
        task => {
          owners.set(task, entry.item);
          expectedTasks.set(entry.item, (expectedTasks.get(entry.item) || 0) + 1);
          scheduler.add(task);
        }
      );
    } catch (error) {
      fail(entry.item, error);
    }
  }

  // run them and record the result per item
  let done = 0;
  const total = owners.size;
  const removeListener = fileService.afterTransfer((error, task) => {
    const item = owners.get(task);
    if (!item) {
      return;
    }

    const outcome = outcomes.get(item)!;
    completedTasks.set(item, (completedTasks.get(item) || 0) + 1);
    if (task.isCancelled()) {
      if (outcome.status === 'done') {
        outcome.status = 'cancelled';
      }
    } else if (error) {
      fail(item, error);
    } else {
      outcome.transferred++;
    }

    done++;
    if (hooks.onTaskDone) {
      hooks.onTaskDone(task, error, done, total);
    }
  });
  const cancelSubscription = token
    ? token.onCancellationRequested(() => fileService.cancelTransferTasks())
    : undefined;

  app.sftpBarItem.startSpinner();
  try {
    await scheduler.run();
  } finally {
    app.sftpBarItem.stopSpinner();
    removeListener();
    if (cancelSubscription) {
      cancelSubscription.dispose();
    }
  }

  // tasks that never started (cancelled while queued)
  entries.forEach(entry => {
    const outcome = outcomes.get(entry.item)!;
    const expected = expectedTasks.get(entry.item) || 0;
    const completed = completedTasks.get(entry.item) || 0;
    if (outcome.status === 'done' && completed < expected) {
      outcome.status = 'cancelled';
    }
  });

  // refresh remote explorer (once per folder) and file decorations (one event) at the end
  const touched = entries.filter(entry => {
    const outcome = outcomes.get(entry.item)!;
    return outcome.status === 'done' || outcome.transferred > 0;
  });
  const refreshedDirs: { [dir: string]: boolean } = {};
  for (const entry of touched) {
    const dir = entry.isDirectory
      ? entry.target.remoteFsPath
      : remoteFs.pathResolver.dirname(entry.target.remoteFsPath);
    if (refreshedDirs[dir]) {
      continue;
    }
    refreshedDirs[dir] = true;
    try {
      await refreshRemoteExplorer(entry.target, entry.isDirectory);
    } catch (error) {
      logger.debug('refresh remote explorer failed', error);
    }
  }
  if (app.decorationProvider && touched.length > 0) {
    app.decorationProvider.invalidateAndRefreshMany(touched.map(entry => entry.item.uri));
  }

  return items.map(item => outcomes.get(item)!);
}
