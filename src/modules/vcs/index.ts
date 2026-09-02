import * as path from 'path';
import { FileService } from '../../core';
import { getAllFileService, getFileService } from '../serviceManager';
import logger from '../../logger';
import { getGitChanges } from './git';
import { findSvnRoot, getSvnChanges } from './svn';
import { VcsChange, ChangeKind } from './types';

export * from './types';

export interface ChangedFile extends VcsChange {
  fileService: FileService;
}

export interface CollectResult {
  changes: ChangedFile[];
  // problems that did not stop the collection (e.g. svn binary missing)
  warnings: string[];
}

// Comparable key for a local path (case-insensitive on windows).
export function pathKey(fsPath: string): string {
  const normalized = path.normalize(fsPath);
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

// When a path is reported more than once (staged + unstaged, git + svn) the higher priority wins.
const KIND_PRIORITY: { [kind in ChangeKind]: number } = {
  conflict: 3,
  renamed: 2,
  added: 2,
  modified: 2,
  untracked: 2,
  deleted: 1,
};

function mergeDuplicates(changes: VcsChange[]): VcsChange[] {
  const byPath = new Map<string, VcsChange>();
  for (const change of changes) {
    const key = pathKey(change.uri.fsPath);
    const existing = byPath.get(key);
    if (!existing || KIND_PRIORITY[change.kind] > KIND_PRIORITY[existing.kind]) {
      byPath.set(key, change);
    }
  }
  return Array.from(byPath.values());
}

// Collect git and svn changes of every configured sftp root that map to a file service.
export async function collectChangedFiles(): Promise<CollectResult> {
  const warnings: string[] = [];
  const services = getAllFileService();
  if (services.length === 0) {
    return { changes: [], warnings };
  }

  let raw: VcsChange[] = [];
  try {
    raw = raw.concat(await getGitChanges());
  } catch (error) {
    warnings.push(`Git: ${error && error.message ? error.message : error}`);
  }

  const visited: { [key: string]: boolean } = {};
  for (const service of services) {
    const key = pathKey(service.baseDir);
    if (visited[key]) {
      continue;
    }
    visited[key] = true;

    const root = await findSvnRoot(service.baseDir);
    if (!root) {
      continue;
    }

    logger.debug(`svn working copy for ${service.baseDir} found at ${root}`);
    try {
      raw = raw.concat(await getSvnChanges(service.baseDir, root));
    } catch (error) {
      warnings.push(error && error.message ? error.message : String(error));
    }
  }

  const changes: ChangedFile[] = [];
  for (const change of mergeDuplicates(raw)) {
    const fileService = getFileService(change.uri);
    if (!fileService) {
      continue;
    }
    changes.push({ ...change, fileService });
  }

  changes.sort((left, right) => {
    const byRoot = left.repositoryRoot.localeCompare(right.repositoryRoot);
    return byRoot !== 0 ? byRoot : left.uri.fsPath.localeCompare(right.uri.fsPath);
  });

  return { changes, warnings };
}
