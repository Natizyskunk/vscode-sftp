import { Uri, EventEmitter } from 'vscode';
import * as path from 'path';
import app from '../../app';
import logger from '../../logger';
import { simplifyPath, reportError } from '../../helper';
import { getActiveTextEditor } from '../../host';
import { UResource, FileService, TransferTask } from '../../core';
import { validateConfig } from '../config';
import watcherService from '../fileWatcher';
import Trie from './trie';

export type TransferEventType = 'queued' | 'start' | 'done' | 'progress';

export interface TransferEvent {
  type: TransferEventType;
  task: TransferTask;
  error?: Error | null;
}

const transferEventEmitter = new EventEmitter<TransferEvent>();
export const onTransferEvent = transferEventEmitter.event;

const WIN_DRIVE_REGEX = /^([a-zA-Z]):/;
const isWindows = process.platform === 'win32';

// tracks aggregate upload/download progress across all file services for the status bar
let queuedTransferCount = 0;
let doneTransferCount = 0;

export function resetTransferProgress() {
  queuedTransferCount = 0;
  doneTransferCount = 0;
  app.transferBarItem.hide();
}

function updateTransferProgress() {
  if (queuedTransferCount === 0) {
    return;
  }

  if (doneTransferCount >= queuedTransferCount) {
    queuedTransferCount = 0;
    doneTransferCount = 0;
    app.transferBarItem.hide();
    return;
  }

  app.transferBarItem.showMsg(`Transferring ${doneTransferCount}/${queuedTransferCount} files`);
  app.transferBarItem.show();
}

const serviceManager = new Trie<FileService>(
  {},
  {
    delimiter: path.sep,
  }
);

function maskConfig(config) {
  const copy = {};
  const MASK = '******';
  Object.keys(config).forEach(key => {
    const configValue = config[key];
    switch (key) {
      case 'username':
      case 'password':
      case 'passphrase':
        copy[key] = MASK;
        break;
      case 'interactiveAuth':
        if (Array.isArray(configValue)) {
          copy[key] = configValue.map(phrase => MASK);
        } else {
          copy[key] = configValue;
        }
        break;
      default:
        copy[key] = configValue;
    }
  });
  return copy;
}

function normalizePathForTrie(pathname) {
  if (isWindows) {
    const device = pathname.substr(0, 2);
    if (device.charAt(1) === ':') {
      // lowercase drive letter
      pathname = pathname[0].toLowerCase() + pathname.substr(1);
    }
  }

  return path.normalize(pathname);
}

export function getBasePath(context: string, workspace: string) {
  let dirpath;
  if (context) {
    if (path.isAbsolute(context)) {
      dirpath = context;
      if (isWindows) {
        const contextBeginWithDrive = context.match(WIN_DRIVE_REGEX);
        // if a windows user omit drive, we complete it with a drive letter same with the workspace one
        if (!contextBeginWithDrive) {
          const workspaceDrive = workspace.match(WIN_DRIVE_REGEX);
          if (workspaceDrive) {
            const drive = workspaceDrive[1];
            dirpath = path.join(`${drive}:`, context);
          }
        }
      }
    } else {
      // Don't use path.resolve bacause it may change the root dir of workspace!
      // Example: On window path.resove('\\a\\b\\c') will result to '<drive>:\\a\\b\\c'
      // We know workspace must be a absolute path and context is a relative path to workspace,
      // so path.join will suit our requirements.
      dirpath = path.join(workspace, context);
    }
  } else {
    dirpath = workspace;
  }

  return normalizePathForTrie(dirpath);
}

function updateAvailableProfiles() {
  const profiles = new Set<string>();
  getAllFileService().forEach(service => {
    service.getAvailableProfiles().forEach(profile => profiles.add(profile));
  });
  app.state.availableProfiles = Array.from(profiles);
}

// drop the active profile when it's no longer defined by any config.
// call this after a config reload has recreated the file services --
// checking during dispose would wrongly reset a still-valid profile.
export function reconcileActiveProfile() {
  if (app.state.profile && !app.state.availableProfiles.includes(app.state.profile)) {
    app.state.profile = null;
  }
}

// recompute the uploadOnSave value shown in the status bar. Prefer the config
// tied to the active editor, falling back to the sole service when there's
// exactly one. Leaves it unknown (null) when it can't be resolved.
export function refreshUploadOnSaveState() {
  let service: FileService | undefined;

  const activeEditor = getActiveTextEditor();
  if (activeEditor) {
    service = getFileService(activeEditor.document.uri);
  }
  if (!service) {
    const services = getAllFileService();
    service = services.length === 1 ? services[0] : undefined;
  }

  if (!service) {
    app.state.uploadOnSave = null;
    return;
  }

  try {
    app.state.uploadOnSave = Boolean(service.getConfig().uploadOnSave);
  } catch (error) {
    app.state.uploadOnSave = null;
  }
}

export function createFileService(config: any, workspace: string) {
  if (config.defaultProfile) {
    app.state.profile = config.defaultProfile;
  }

  const normalizedBasePath = getBasePath(config.context, workspace);
  const service = new FileService(normalizedBasePath, workspace, config);

  logger.info(`config at ${normalizedBasePath}`, maskConfig(config));

  serviceManager.add(normalizedBasePath, service);
  service.name = config.name;
  service.setConfigValidator(validateConfig);
  service.setWatcherService(watcherService);
  service.onQueueTransfer(task => {
    queuedTransferCount++;
    updateTransferProgress();
    transferEventEmitter.fire({ type: 'queued', task });
  });
  service.beforeTransfer(task => {
    const { localFsPath, transferType } = task;
    app.sftpBarItem.showMsg(
      `${transferType} ${path.basename(localFsPath)}`,
      simplifyPath(localFsPath)
    );
    transferEventEmitter.fire({ type: 'start', task });
  });
  service.onProgressTransfer(task => {
    transferEventEmitter.fire({ type: 'progress', task });
  });
  service.afterTransfer((error, task) => {
    const { localFsPath, transferType } = task;
    const filename = path.basename(localFsPath);
    const filepath = simplifyPath(localFsPath);
    if (task.isCancelled()) {
      logger.info(`cancel transfer ${localFsPath}`);
      app.sftpBarItem.showMsg(`cancelled ${filename}`, filepath, 2000 * 2);
    } else if (error) {
      // if ((error as any).reported !== true) {
      reportError(error, `when ${transferType} ${localFsPath}`);
      // }
      app.sftpBarItem.showMsg(`failed ${filename}`, filepath, 2000 * 2);
    } else {
      logger.info(`${transferType} ${localFsPath}`);
      app.sftpBarItem.showMsg(`done ${filename}`, filepath, 2000 * 2);
    }
    doneTransferCount++;
    updateTransferProgress();
    transferEventEmitter.fire({ type: 'done', task, error });
  });
  updateAvailableProfiles();

  return service;
}

export function getFileService(uri: Uri): FileService {
  let fileService;
  if (UResource.isRemote(uri)) {
    const remoteRoot = app.remoteExplorer.findRoot(uri);
    if (remoteRoot) {
      fileService = remoteRoot.explorerContext.fileService;
    }
  } else {
    fileService = serviceManager.findPrefix(normalizePathForTrie(uri.fsPath));
  }

  return fileService;
}

export function disposeFileService(fileService: FileService) {
  serviceManager.remove(fileService.baseDir);
  fileService.dispose();
  updateAvailableProfiles();
}

export function findAllFileService(predictor: (x: FileService) => boolean): FileService[] {
  if (serviceManager === undefined) {
    return [];
  }

  return getAllFileService().filter(predictor);
}

export function getAllFileService(): FileService[] {
  if (serviceManager === undefined) {
    return [];
  }

  return serviceManager.getAllValues();
}

export function getRunningTransformTasks(): TransferTask[] {
  return getAllFileService().reduce<TransferTask[]>((acc, fileService) => {
    return acc.concat(fileService.getPendingTransferTasks());
  }, []);
}
