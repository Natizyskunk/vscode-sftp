import { window } from 'vscode';
import { FileType } from '../../core';
import logger from '../../logger';
import { FileHandlerContext } from '../createFileHandler';
import { getRemoteBaseline, recordRemoteBaseline } from './remoteBaseline';

export interface FileStat {
  mtime: number;
  size: number;
}

export type ConflictVerdict = 'proceed' | 'conflict';

// Compare at second granularity: a transfer writes the source mtime onto the
// target with futimes(), which truncates to whole seconds, so two sides of the
// same file routinely differ by sub-second noise.
function sameFile(a: FileStat, b: FileStat): boolean {
  return Math.floor(a.mtime / 1000) === Math.floor(b.mtime / 1000) && a.size === b.size;
}

/**
 * Decide whether uploading `local` would clobber a remote change we never saw.
 *
 * `baseline` is what the remote looked like the last time we transferred this
 * file (see remoteBaseline). It is what makes the "you edited after their
 * change" case detectable: once the local file is touched, its mtime is newer
 * than the remote's, so local-vs-remote mtime alone would call that safe.
 */
export function detectUploadConflict(
  local: FileStat,
  remote: FileStat | null,
  baseline: FileStat | null
): ConflictVerdict {
  // Nothing on the remote to lose.
  if (!remote) {
    return 'proceed';
  }

  // The remote already is our file — the normal state right after we uploaded
  // it (including as part of a folder upload or sync, which record no baseline).
  if (sameFile(remote, local)) {
    return 'proceed';
  }

  // We know what we last left there: anything else means someone changed it.
  if (baseline) {
    return sameFile(remote, baseline) ? 'proceed' : 'conflict';
  }

  // No baseline (first upload this workspace has seen for the file). Fall back
  // to mtime: a remote newer than our copy was written after we last got it.
  return Math.floor(remote.mtime / 1000) > Math.floor(local.mtime / 1000)
    ? 'conflict'
    : 'proceed';
}

async function statOrNull(fs, fsPath: string): Promise<(FileStat & { type: FileType }) | null> {
  try {
    const stat = await fs.lstat(fsPath);
    return { mtime: stat.mtime, size: stat.size, type: stat.type };
  } catch (error) {
    return null;
  }
}

function describe(stat: FileStat): string {
  return `${new Date(stat.mtime).toLocaleString()} (${stat.size} bytes)`;
}

function basename(fsPath: string): string {
  return fsPath.split(/[\\/]/).pop() || fsPath;
}

// 'diff' asks the caller to open the diff view; the upload is off either way.
export type UploadDecision = 'proceed' | 'cancel' | 'diff';

/**
 * Pre-upload guard, gated by the `conflictCheck` config option (default off).
 *
 * Only single-file uploads are checked. A folder upload would mean prompting
 * per file mid-transfer; use Sync (with `syncConfirm`) to review a tree.
 */
export async function confirmUpload(ctx: FileHandlerContext): Promise<UploadDecision> {
  if (!ctx.config.conflictCheck) {
    return 'proceed';
  }

  const { localFsPath, remoteFsPath } = ctx.target;

  const local = await statOrNull(ctx.fileService.getLocalFileSystem(), localFsPath);
  // Not a single file (folder upload), or gone — leave it to the transfer.
  if (!local || local.type === FileType.Directory) {
    return 'proceed';
  }

  const remoteFs = await ctx.fileService.getRemoteFileSystem(ctx.config);
  const remote = await statOrNull(remoteFs, remoteFsPath);
  if (remote && remote.type === FileType.Directory) {
    return 'proceed';
  }

  const verdict = detectUploadConflict(local, remote, getRemoteBaseline(ctx));
  if (verdict === 'proceed') {
    return 'proceed';
  }

  logger.info(`[conflict-check] remote changed since last transfer: ${remoteFsPath}`);

  const choice = await window.showWarningMessage(
    `The remote copy of ${basename(localFsPath)} changed since you last downloaded or ` +
      `uploaded it. Uploading will overwrite those changes.`,
    {
      modal: true,
      detail:
        `Remote: ${describe(remote!)}\nLocal:  ${describe(local)}\n\n` +
        `Open Diff compares the two and leaves the remote untouched.`,
    },
    'Overwrite',
    'Open Diff'
  );

  switch (choice) {
    case 'Overwrite':
      return 'proceed';
    case 'Open Diff':
      return 'diff';
    default:
      return 'cancel';
  }
}

/**
 * Remember what the remote looks like now, so a later upload can tell our own
 * writes apart from someone else's. Called after a transfer settles; best
 * effort, and only when the feature is on (it costs a stat round-trip).
 */
export async function updateBaselineAfterTransfer(ctx: FileHandlerContext): Promise<void> {
  if (!ctx.config.conflictCheck) {
    return;
  }

  try {
    const remoteFs = await ctx.fileService.getRemoteFileSystem(ctx.config);
    const remote = await statOrNull(remoteFs, ctx.target.remoteFsPath);
    if (remote && remote.type !== FileType.Directory) {
      recordRemoteBaseline(ctx, { mtime: remote.mtime, size: remote.size });
    }
  } catch (error) {
    logger.warn(error, 'failed to record remote baseline');
  }
}
