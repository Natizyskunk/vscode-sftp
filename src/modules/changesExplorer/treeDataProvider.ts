import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { FileService } from '../../core';
import { getFileService } from '../serviceManager';
import { getGitService, Change, Status } from '../git';

export type Scope = 'workingTree' | 'branch';

export type ChangeNode =
  | { kind: 'context'; service: FileService; changes: Change[] }
  | { kind: 'file'; change: Change; service: FileService };

export function statusLabel(status: Status): string {
  switch (status) {
    case Status.INDEX_MODIFIED:
    case Status.MODIFIED:
      return 'M';
    case Status.INDEX_ADDED:
    case Status.UNTRACKED:
      return 'A';
    case Status.INDEX_DELETED:
    case Status.DELETED:
      return 'D';
    case Status.INDEX_RENAMED:
      return 'R';
    default:
      return '';
  }
}

// git reports submodules as changes too, but their uri is a directory — uploading
// it would recurse the whole submodule. Only individual files are uploadable.
function isExistingDirectory(fsPath: string): boolean {
  try {
    return fs.statSync(fsPath).isDirectory();
  } catch (e) {
    return false; // deleted files don't exist locally -> not a dir, keep them
  }
}

// the branch this feature branch was likely cut from
function findBaseRef(repo: any): string | null {
  const candidates = ['main', 'master', 'origin/main', 'origin/master'];
  const refNames = new Set(
    (repo.state.refs || []).map((r: any) => r.name).filter(Boolean)
  );
  for (const name of candidates) {
    if (refNames.has(name)) {
      return name;
    }
  }
  return null;
}

// changed files that map to an SFTP context, grouped by context.
//  - workingTree: uncommitted (index + working tree)
//  - branch: everything the current branch touched vs its base, plus uncommitted
export async function collectChanges(
  scope: Scope
): Promise<Map<FileService, Change[]>> {
  const map = new Map<FileService, Change[]>();
  let git: any;
  try {
    git = getGitService();
  } catch (e) {
    return map;
  }
  if (!git) {
    return map;
  }

  const seen = new Set<string>();
  for (const repo of git.repositories) {
    let changes: Change[] = repo.state.indexChanges.concat(
      repo.state.workingTreeChanges
    );

    if (scope === 'branch') {
      const base = findBaseRef(repo);
      const head = repo.state.HEAD && repo.state.HEAD.name;
      if (base && base !== head) {
        try {
          const branchChanges: Change[] = await repo.diffBetween(base, 'HEAD');
          changes = changes.concat(branchChanges);
        } catch (e) {
          /* base unreachable -> just show uncommitted */
        }
      }
    }

    for (const change of changes) {
      const service = getFileService(change.uri);
      if (!service) {
        continue;
      }
      // skip submodules / directories — not individual uploadable files
      if (isExistingDirectory(change.uri.fsPath)) {
        continue;
      }
      const key = service.baseDir + '|' + change.uri.fsPath;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      const arr = map.get(service) || [];
      arr.push(change);
      map.set(service, arr);
    }
  }
  return map;
}

export default class ChangesTreeDataProvider
  implements vscode.TreeDataProvider<ChangeNode> {
  private _onDidChange = new vscode.EventEmitter<ChangeNode | undefined>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  scope: Scope = 'workingTree';

  refresh() {
    this._onDidChange.fire(undefined);
  }

  getFlatChanges(): Promise<Change[]> {
    return collectChanges(this.scope).then(grouped => {
      const all: Change[] = [];
      grouped.forEach(changes => all.push(...changes));
      return all;
    });
  }

  async getChildren(element?: ChangeNode): Promise<ChangeNode[]> {
    if (!element) {
      const grouped = await collectChanges(this.scope);
      const nodes: ChangeNode[] = [];
      grouped.forEach((changes, service) =>
        nodes.push({ kind: 'context', service, changes })
      );
      return nodes;
    }
    if (element.kind === 'context') {
      return element.changes.map(change => ({
        kind: 'file' as const,
        change,
        service: element.service,
      }));
    }
    return [];
  }

  getTreeItem(node: ChangeNode): vscode.TreeItem {
    if (node.kind === 'context') {
      const item = new vscode.TreeItem(
        node.service.name || path.basename(node.service.baseDir),
        vscode.TreeItemCollapsibleState.Expanded
      );
      const profile = node.service.getActiveProfile();
      item.description = `${node.changes.length} changed${profile ? ` · ${profile}` : ''}`;
      item.iconPath = new vscode.ThemeIcon('server-environment');
      item.contextValue = 'sftpChangesContext';
      return item;
    }

    const change = node.change;
    const item = new vscode.TreeItem(path.basename(change.uri.fsPath));
    item.resourceUri = change.uri; // inherit VS Code's git color/badge decorations
    item.description = statusLabel(change.status);
    item.tooltip = change.uri.fsPath;
    item.contextValue = 'sftpChangesFile';
    item.command = {
      command: 'vscode.open',
      title: 'Open',
      arguments: [change.uri],
    };
    return item;
  }
}
