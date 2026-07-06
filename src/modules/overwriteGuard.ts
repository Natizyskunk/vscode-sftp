import * as vscode from 'vscode';
import * as path from 'path';
import { COMMAND_DIFF } from '../constants';

// localFsPath -> remote version we last synced (on open / after download / after
// upload). Lets us detect, before the next upload, when someone else changed the
// file in between and avoid silently overwriting their work. Opt-in via the
// `uploadGuard` config option.
interface Baseline {
  mtime: number;
  remotePath: string;
}
const baseline = new Map<string, Baseline>();

async function statMtime(fs: any, remotePath: string): Promise<number | null> {
  try {
    const stat = await fs.lstat(remotePath);
    return stat.mtime;
  } catch (e) {
    // remote file missing or unreachable -> treat as "no known remote version"
    return null;
  }
}

async function getRemoteFs(ctx: any): Promise<any> {
  return ctx.fileService.getRemoteFileSystem(ctx.config);
}

// Record the current remote version as our baseline.
export async function rememberRemoteVersion(ctx: any): Promise<void> {
  if (!ctx.config.uploadGuard) {
    return;
  }
  const remotePath = ctx.target.remoteFsPath;
  const mtime = await statMtime(await getRemoteFs(ctx), remotePath);
  if (mtime === null) {
    baseline.delete(ctx.target.localFsPath);
  } else {
    baseline.set(ctx.target.localFsPath, { mtime, remotePath });
  }
}

// drop baselines under a folder (e.g. after a bulk upload overwrote them)
export function forgetUnder(folder: string) {
  const prefix = folder.endsWith(path.sep) ? folder : folder + path.sep;
  for (const key of Array.from(baseline.keys())) {
    if (key === folder || key.startsWith(prefix)) {
      baseline.delete(key);
    }
  }
}

// Single-file upload guard. Returns false to abort (Cancel or Show Diff).
export async function guardUpload(ctx: any): Promise<boolean> {
  if (!ctx.config.uploadGuard) {
    return true;
  }

  const localPath = ctx.target.localFsPath;
  const entry = baseline.get(localPath);
  // No baseline this session -> nothing to compare against, let it through.
  if (entry === undefined) {
    return true;
  }

  const current = await statMtime(await getRemoteFs(ctx), entry.remotePath);
  // Remote gone or unchanged since we last synced -> safe to upload.
  if (current === null || current === entry.mtime) {
    return true;
  }

  const choice = await vscode.window.showWarningMessage(
    `The remote file "${ctx.target.remoteFsPath}" changed since you opened it — ` +
      `another user may have edited it. Overwrite their changes?`,
    { modal: true },
    'Overwrite',
    'Show Diff'
  );

  if (choice === 'Show Diff') {
    await vscode.commands.executeCommand(COMMAND_DIFF, ctx.target.localUri);
    return false;
  }
  if (choice === 'Overwrite') {
    baseline.set(localPath, { mtime: current, remotePath: entry.remotePath });
    return true;
  }
  return false;
}

// Folder/project upload guard. Among files you opened that live under this
// folder, warn (once) if any changed on the remote since you opened them.
export async function guardBulkUpload(ctx: any): Promise<boolean> {
  if (!ctx.config.uploadGuard) {
    return true;
  }

  const folder = ctx.target.localFsPath;
  const prefix = folder.endsWith(path.sep) ? folder : folder + path.sep;
  const fs = await getRemoteFs(ctx);

  const changed: string[] = [];
  for (const [localPath, entry] of baseline) {
    if (localPath !== folder && !localPath.startsWith(prefix)) {
      continue;
    }
    const current = await statMtime(fs, entry.remotePath);
    if (current !== null && current !== entry.mtime) {
      changed.push(localPath);
    }
  }

  if (changed.length === 0) {
    return true;
  }

  const list = changed.map(p => path.basename(p)).join(', ');
  const choice = await vscode.window.showWarningMessage(
    `${changed.length} file(s) you opened changed on the remote since then ` +
      `(${list}). Uploading this folder will overwrite them. Continue?`,
    { modal: true },
    'Overwrite all'
  );
  return choice === 'Overwrite all';
}
