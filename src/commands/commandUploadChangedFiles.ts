import * as vscode from 'vscode';
import * as path from 'path';
import { COMMAND_UPLOAD_CHANGEDFILES, EXTENSION_NAME } from '../constants';
import { FileService } from '../core';
import {
  removeRemote,
  renameRemote,
  handleCtxFromUri,
  uploadBatch,
  BatchOutcome,
} from '../fileHandlers';
import { collectChangedFiles, ChangedFile, ChangeKind, pathKey } from '../modules/vcs';
import { checkCommand } from './abstract/createCommand';
import { getUserSetting, showInformationMessage, showWarningMessage } from '../host';
import * as output from '../ui/output';
import app from '../app';
import logger from '../logger';
import { simplifyPath } from '../helper';

export default checkCommand({
  id: COMMAND_UPLOAD_CHANGEDFILES,

  async handleCommand(hint: any) {
    await uploadChangedFiles(hint);
  },
});

interface ChangedFilesSetting {
  confirm: boolean;
  includeUntracked: boolean;
  allowRemoteDelete: boolean;
}

interface Outcome {
  change: ChangedFile;
  reason?: string;
}

interface RunResult {
  uploaded: Outcome[];
  renamed: Outcome[];
  deleted: Outcome[];
  skipped: Outcome[];
  failed: Outcome[];
}

interface ChangeQuickPickItem extends vscode.QuickPickItem {
  change: ChangedFile;
}

type ProgressReporter = vscode.Progress<{ message?: string; increment?: number }>;

const KIND_ICON: { [kind in ChangeKind]: string } = {
  added: 'diff-added',
  modified: 'diff-modified',
  deleted: 'diff-removed',
  renamed: 'diff-renamed',
  untracked: 'new-file',
  conflict: 'warning',
};

const KIND_LABEL: { [kind in ChangeKind]: string } = {
  added: 'added',
  modified: 'modified',
  deleted: 'delete on remote',
  renamed: 'renamed',
  untracked: 'untracked',
  conflict: 'conflict',
};

function getSetting(): ChangedFilesSetting {
  const setting = getUserSetting(EXTENSION_NAME);
  return {
    confirm: setting.get<boolean>('changedFiles.confirm', true),
    includeUntracked: setting.get<boolean>('changedFiles.includeUntracked', true),
    allowRemoteDelete: setting.get<boolean>('changedFiles.allowRemoteDelete', false),
  };
}

function errorMessage(error: any): string {
  return error && error.message ? error.message : String(error);
}

function isSourceControlResourceGroup(object: any): object is vscode.SourceControlResourceGroup {
  return !!object && typeof object === 'object' && 'id' in object && 'resourceStates' in object;
}

function isSourceControl(object: any): object is vscode.SourceControl {
  return !!object && typeof object === 'object' && 'rootUri' in object;
}

function isInside(root: string, fsPath: string): boolean {
  const rootKey = pathKey(root).replace(/[\\/]+$/, '');
  const fileKey = pathKey(fsPath);
  return fileKey === rootKey || fileKey.indexOf(rootKey + path.sep) === 0;
}

// Restrict the changes to what was clicked in the Source Control view (group or repository).
function createScopeFilter(hint: any): (change: ChangedFile) => boolean {
  if (isSourceControlResourceGroup(hint)) {
    const keys: { [key: string]: boolean } = {};
    hint.resourceStates.forEach(state => {
      keys[pathKey(state.resourceUri.fsPath)] = true;
    });
    return change =>
      keys[pathKey(change.uri.fsPath)] === true ||
      (change.originalUri !== undefined && keys[pathKey(change.originalUri.fsPath)] === true);
  }

  if (isSourceControl(hint) && hint.rootUri) {
    const root = hint.rootUri.fsPath;
    return change => isInside(root, change.uri.fsPath);
  }

  return () => true;
}

function describeChange(change: ChangedFile): string {
  const parts: string[] = [];
  if (change.kind === 'renamed' && change.originalUri) {
    parts.push(`renamed from ${simplifyPath(change.originalUri.fsPath)}`);
  } else {
    parts.push(KIND_LABEL[change.kind]);
  }
  parts.push(change.vcs.toUpperCase());

  const target = change.fileService.name || change.fileService.getConfig().host;
  if (target) {
    parts.push(target);
  }
  return parts.join(' · ');
}

async function pickChanges(changes: ChangedFile[]): Promise<ChangedFile[] | undefined> {
  const items: ChangeQuickPickItem[] = changes.map(change => ({
    label: `$(${KIND_ICON[change.kind]}) ${simplifyPath(change.uri.fsPath)}`,
    description: describeChange(change),
    picked: change.kind !== 'deleted',
    change,
  }));

  const picked = await vscode.window.showQuickPick(items, {
    canPickMany: true,
    ignoreFocusOut: true,
    matchOnDescription: true,
    placeHolder: `Select the changed files to upload (${changes.length} found)`,
  });

  return picked ? picked.map(item => item.change) : undefined;
}

function isNotFoundError(error: any): boolean {
  if (!error) {
    return false;
  }
  // local: ENOENT, sftp: SSH_FX_NO_SUCH_FILE (2), ftp: 550
  if (error.code === 'ENOENT' || error.code === 2 || error.code === 550) {
    return true;
  }
  return /no such file|not found|does not exist|file unavailable/i.test(
    String(error.message || error)
  );
}

function isIgnored(change: ChangedFile): boolean {
  const config = change.fileService.getConfig();
  return (
    !!config.useIgnoreForUpload &&
    typeof config.ignore === 'function' &&
    config.ignore(change.uri.fsPath)
  );
}

// Try to move the old remote file to the new path. The new path is uploaded afterwards anyway.
async function renameOnRemote(change: ChangedFile): Promise<boolean> {
  if (!change.originalUri) {
    return false;
  }

  try {
    const originalTarget = handleCtxFromUri(change.originalUri).target;
    await renameRemote(change.uri, { originPath: originalTarget.remoteFsPath });
    return true;
  } catch (error) {
    const reason = isNotFoundError(error) ? 'not found on remote' : errorMessage(error);
    logger.warn(
      `Remote rename of ${change.originalUri.fsPath} skipped (${reason}). Uploading ${change.uri.fsPath} instead.`
    );
    return false;
  }
}

async function execute(
  toProcess: ChangedFile[],
  result: RunResult,
  progress: ProgressReporter,
  token: vscode.CancellationToken
) {
  const uploads: ChangedFile[] = [];
  const deletes: ChangedFile[] = [];
  for (const change of toProcess) {
    if (change.kind === 'deleted') {
      deletes.push(change);
      continue;
    }
    if (change.kind === 'conflict') {
      result.skipped.push({ change, reason: 'conflict, resolve it first' });
      continue;
    }
    if (isIgnored(change)) {
      result.skipped.push({ change, reason: 'ignored by ignore list' });
      continue;
    }
    if (change.kind === 'renamed' && !token.isCancellationRequested) {
      progress.report({ message: `rename ${path.basename(change.uri.fsPath)}` });
      if (await renameOnRemote(change)) {
        result.renamed.push({ change });
      }
    }
    uploads.push(change);
  }

  // one batch per file service: folders are created once, all files share one scheduler
  const groups = new Map<FileService, ChangedFile[]>();
  uploads.forEach(change => {
    const list = groups.get(change.fileService) || [];
    list.push(change);
    groups.set(change.fileService, list);
  });

  for (const [fileService, changes] of Array.from(groups.entries())) {
    if (token.isCancellationRequested) {
      changes.forEach(change => result.skipped.push({ change, reason: 'cancelled' }));
      continue;
    }

    let outcomes: BatchOutcome<ChangedFile>[];
    try {
      outcomes = await uploadBatch(fileService, changes, {
        token,
        onTaskDone: (task, _error, done, total) => {
          progress.report({ message: `${done}/${total} ${path.basename(task.localFsPath)}` });
        },
      });
    } catch (error) {
      // e.g. connection failed
      logger.error(error, `upload changed files to ${fileService.name || fileService.baseDir}`);
      const reason = errorMessage(error);
      changes.forEach(change => result.failed.push({ change, reason }));
      continue;
    }

    for (const outcome of outcomes) {
      const change = outcome.item;
      switch (outcome.status) {
        case 'done':
          if (!result.renamed.some(item => item.change === change)) {
            result.uploaded.push({ change });
          }
          break;
        case 'cancelled':
          result.skipped.push({ change, reason: 'cancelled' });
          break;
        default:
          result.failed.push({ change, reason: errorMessage(outcome.error) });
      }
    }
  }

  for (const change of deletes) {
    if (token.isCancellationRequested) {
      result.skipped.push({ change, reason: 'cancelled' });
      continue;
    }
    progress.report({ message: `delete ${path.basename(change.uri.fsPath)}` });
    try {
      await removeRemote(change.uri);
      result.deleted.push({ change });
    } catch (error) {
      if (isNotFoundError(error)) {
        result.skipped.push({ change, reason: 'not found on remote' });
      } else {
        logger.error(error, `delete remote file ${change.uri.fsPath}`);
        result.failed.push({ change, reason: errorMessage(error) });
      }
    }
  }
}

function formatChange(outcome: Outcome): string {
  const filePath = simplifyPath(outcome.change.uri.fsPath);
  return outcome.reason ? `${filePath} (${outcome.reason})` : filePath;
}

function formatRename(outcome: Outcome): string {
  const from = outcome.change.originalUri ? simplifyPath(outcome.change.originalUri.fsPath) : '?';
  return `${from} ➞ ${simplifyPath(outcome.change.uri.fsPath)}`;
}

function logGroup(label: string, outcomes: Outcome[], format: (outcome: Outcome) => string) {
  if (outcomes.length <= 0) {
    return;
  }
  logger.log(`${label.toUpperCase()} (${outcomes.length}):`);
  logger.log(outcomes.map(format).join('\n'));
  logger.log('');
}

function logSummary(result: RunResult) {
  logger.log('');
  logger.log('------ Upload Changed Files Result ------');
  logGroup('uploaded', result.uploaded, formatChange);
  logGroup('renamed', result.renamed, formatRename);
  logGroup('deleted', result.deleted, formatChange);
  logGroup('skipped', result.skipped, formatChange);
  logGroup('failed', result.failed, formatChange);
}

function summarize(result: RunResult): string {
  const parts = [`${result.uploaded.length} uploaded`];
  if (result.renamed.length) {
    parts.push(`${result.renamed.length} renamed`);
  }
  if (result.deleted.length) {
    parts.push(`${result.deleted.length} deleted`);
  }
  if (result.skipped.length) {
    parts.push(`${result.skipped.length} skipped`);
  }
  if (result.failed.length) {
    parts.push(`${result.failed.length} failed`);
  }
  return parts.join(', ');
}

async function uploadChangedFiles(hint: any) {
  const setting = getSetting();
  const collected = await collectChangedFiles();
  collected.warnings.forEach(warning => {
    logger.warn(warning);
    showWarningMessage(warning);
  });

  const inScope = createScopeFilter(hint);
  const excluded: Outcome[] = [];
  const candidates = collected.changes.filter(change => {
    if (!inScope(change)) {
      return false;
    }
    if (change.kind === 'untracked' && !setting.includeUntracked) {
      excluded.push({ change, reason: 'untracked, see sftp.changedFiles.includeUntracked' });
      return false;
    }
    if (change.kind === 'deleted' && !setting.allowRemoteDelete) {
      excluded.push({ change, reason: 'deleted locally, see sftp.changedFiles.allowRemoteDelete' });
      return false;
    }
    if (change.kind === 'conflict') {
      excluded.push({ change, reason: 'conflict, resolve it first' });
      return false;
    }
    return true;
  });

  if (candidates.length === 0) {
    logSummary({ uploaded: [], renamed: [], deleted: [], skipped: excluded, failed: [] });
    showInformationMessage(
      excluded.length
        ? `No changed files to upload (${excluded.length} skipped, see SFTP output).`
        : 'No changed files to upload.'
    );
    return;
  }

  let selected: ChangedFile[] | undefined;
  if (setting.confirm) {
    selected = await pickChanges(candidates);
    if (!selected) {
      logger.info('Upload Changed Files cancelled.');
      return;
    }
    const picked = selected;
    candidates
      .filter(change => picked.indexOf(change) === -1)
      .forEach(change => excluded.push({ change, reason: 'deselected' }));
  } else {
    selected = candidates.filter(change => change.kind !== 'deleted');
    candidates
      .filter(change => change.kind === 'deleted')
      .forEach(change =>
        excluded.push({
          change,
          reason: 'deletion needs confirmation, see sftp.changedFiles.confirm',
        })
      );
  }

  const toProcess = selected;
  if (toProcess.length === 0) {
    showInformationMessage('No files selected for upload.');
    return;
  }

  const result: RunResult = {
    uploaded: [],
    renamed: [],
    deleted: [],
    skipped: excluded,
    failed: [],
  };

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'SFTP: Upload Changed Files',
      cancellable: true,
    },
    (progress, token) => execute(toProcess, result, progress, token)
  );

  // safety net: everything that got no outcome counts as cancelled
  const handled = ([] as Outcome[])
    .concat(result.uploaded, result.renamed, result.deleted, result.skipped, result.failed)
    .map(outcome => outcome.change);
  toProcess
    .filter(change => handled.indexOf(change) === -1)
    .forEach(change => result.skipped.push({ change, reason: 'cancelled' }));

  logSummary(result);
  const summary = summarize(result);
  app.sftpBarItem.showMsg('changed files uploaded', summary, 5000);

  const message = `Upload Changed Files: ${summary}`;
  const show = result.failed.length
    ? showWarningMessage(message, 'Show Output')
    : showInformationMessage(message, 'Show Output');
  show.then(action => {
    if (action === 'Show Output') {
      output.show();
    }
  });
}
