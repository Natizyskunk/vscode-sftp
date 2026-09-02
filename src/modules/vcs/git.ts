import * as vscode from 'vscode';
import { GitExtension, API, Status, Change } from '../git/git';
import { VcsChange, ChangeKind } from './types';
import logger from '../../logger';

async function getGitApi(): Promise<API | undefined> {
  const extension = vscode.extensions.getExtension<GitExtension>('vscode.git');
  if (!extension) {
    return undefined;
  }

  try {
    const gitExtension = extension.isActive ? extension.exports : await extension.activate();
    if (!gitExtension || !gitExtension.enabled) {
      return undefined;
    }
    return gitExtension.getAPI(1);
  } catch (error) {
    logger.warn('Git extension is not available.', error);
    return undefined;
  }
}

function mapStatus(status: Status): ChangeKind | undefined {
  switch (status) {
    case Status.INDEX_MODIFIED:
    case Status.MODIFIED:
      return 'modified';
    case Status.INDEX_ADDED:
    case Status.INDEX_COPIED:
      return 'added';
    case Status.UNTRACKED:
      return 'untracked';
    case Status.INDEX_RENAMED:
      return 'renamed';
    case Status.INDEX_DELETED:
    case Status.DELETED:
      return 'deleted';
    case Status.ADDED_BY_US:
    case Status.ADDED_BY_THEM:
    case Status.DELETED_BY_US:
    case Status.DELETED_BY_THEM:
    case Status.BOTH_ADDED:
    case Status.BOTH_DELETED:
    case Status.BOTH_MODIFIED:
      return 'conflict';
    default:
      // IGNORED and anything unknown
      return undefined;
  }
}

function toVcsChange(change: Change, root: string): VcsChange | undefined {
  const kind = mapStatus(change.status);
  if (!kind) {
    return undefined;
  }

  if (kind === 'renamed') {
    return {
      vcs: 'git',
      kind,
      uri: change.renameUri || change.uri,
      originalUri: change.originalUri,
      repositoryRoot: root,
    };
  }

  return { vcs: 'git', kind, uri: change.uri, repositoryRoot: root };
}

// Changes of every repository opened by the git extension (merge, index and working tree).
export async function getGitChanges(): Promise<VcsChange[]> {
  const api = await getGitApi();
  if (!api) {
    return [];
  }

  const result: VcsChange[] = [];
  for (const repository of api.repositories) {
    const root = repository.rootUri.fsPath;
    const { mergeChanges, indexChanges, workingTreeChanges } = repository.state;
    for (const change of mergeChanges.concat(indexChanges, workingTreeChanges)) {
      const mapped = toVcsChange(change, root);
      if (mapped) {
        result.push(mapped);
      }
    }
  }

  return result;
}
