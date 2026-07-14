import { window } from 'vscode';
import { TransferDirection } from '../core';
import { compareFolders, CompareResult } from './compareFolders';
import { FileHandlerContext } from './createFileHandler';

// The subset of a sync's transferOption that affects what a sync would do.
export interface SyncPreviewOption {
  delete?: boolean;
  skipCreate?: boolean;
  ignoreExisting?: boolean;
  update?: boolean;
  bothDiretions?: boolean;
}

export interface SyncPlan {
  create: string[];
  overwrite: string[];
  delete: string[];
}

const MAX_DETAIL_LINES = 40;

// Classify the recursive local/remote diff into the operations a sync would
// perform, honoring the same syncOption flags the real sync respects. A
// local-only / remote-only directory shows up as a single entry (its subtree
// is not expanded) — good enough for a summary preview.
export function computeSyncPlan(
  results: CompareResult[],
  direction: TransferDirection,
  option: SyncPreviewOption
): SyncPlan {
  const plan: SyncPlan = { create: [], overwrite: [], delete: [] };

  if (option.bothDiretions) {
    // Both-directions keeps the newest copy on each side and never deletes;
    // only skipCreate and ignoreExisting apply (matches the sync handler).
    for (const r of results) {
      if (r.status === 'localOnly' || r.status === 'remoteOnly') {
        if (!option.skipCreate) plan.create.push(r.relativePath);
      } else if (r.status === 'modified') {
        if (!option.ignoreExisting) plan.overwrite.push(r.relativePath);
      }
    }
    return plan;
  }

  const isLocalToRemote = direction === TransferDirection.LOCAL_TO_REMOTE;
  const srcOnly = isLocalToRemote ? 'localOnly' : 'remoteOnly';
  const destOnly = isLocalToRemote ? 'remoteOnly' : 'localOnly';

  for (const r of results) {
    if (r.status === srcOnly) {
      if (!option.skipCreate) plan.create.push(r.relativePath);
    } else if (r.status === destOnly) {
      if (option.delete) plan.delete.push(r.relativePath);
    } else if (r.status === 'modified') {
      const srcNewer = isLocalToRemote
        ? r.localMtime > r.remoteMtime
        : r.remoteMtime > r.localMtime;
      if (!option.ignoreExisting && (!option.update || srcNewer)) {
        plan.overwrite.push(r.relativePath);
      }
    }
  }

  return plan;
}

function pluralize(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

function buildDetail(plan: SyncPlan, createLabel: string): string {
  const lines: string[] = [];
  plan.create.forEach(p => lines.push(`+ ${createLabel}: ${p}`));
  plan.overwrite.forEach(p => lines.push(`~ overwrite: ${p}`));
  plan.delete.forEach(p => lines.push(`- delete: ${p}`));

  if (lines.length > MAX_DETAIL_LINES) {
    const shown = lines.slice(0, MAX_DETAIL_LINES);
    shown.push(`… and ${lines.length - MAX_DETAIL_LINES} more`);
    return shown.join('\n');
  }
  return lines.join('\n');
}

// Decide whether the sync should proceed. When syncConfirm resolves to true,
// build a dry-run preview and ask for confirmation; otherwise run unchanged.
// The preview walks the tree once here and the sync walks it again — accepted
// for v1, and only paid when confirmation is actually enabled.
export async function confirmSyncOrProceed(
  ctx: FileHandlerContext,
  direction: TransferDirection,
  option: SyncPreviewOption
): Promise<boolean> {
  const deleteEnabled = !!option.delete && !option.bothDiretions;

  // Explicit default: honor syncConfirm when set, otherwise default to true
  // only when a sync could delete files (the destructive case).
  const configConfirm = (ctx.config as any).syncConfirm;
  const enabled = configConfirm !== undefined ? !!configConfirm : deleteEnabled;
  if (!enabled) {
    return true;
  }

  const results = await compareFolders(ctx);
  const plan = computeSyncPlan(results, direction, option);
  const total = plan.create.length + plan.overwrite.length + plan.delete.length;

  const dirLabel = option.bothDiretions
    ? 'Both Directions'
    : direction === TransferDirection.LOCAL_TO_REMOTE
    ? 'Local → Remote'
    : 'Remote → Local';

  if (total === 0) {
    window.showInformationMessage(
      `SFTP Sync ${dirLabel}: nothing to do — local and remote already match.`
    );
    return false;
  }

  const createLabel = option.bothDiretions
    ? 'transfer'
    : direction === TransferDirection.LOCAL_TO_REMOTE
    ? 'upload'
    : 'download';

  const parts = [
    pluralize(plan.create.length, createLabel),
    pluralize(plan.overwrite.length, 'overwrite'),
  ];
  if (!option.bothDiretions) {
    parts.push(pluralize(plan.delete.length, 'deletion'));
  }

  const summary = `Sync ${dirLabel}: ${parts.join(', ')}. Proceed?`;
  const detail = buildDetail(plan, createLabel);

  const choice = await window.showWarningMessage(
    summary,
    { modal: true, detail },
    'Proceed'
  );
  return choice === 'Proceed';
}
