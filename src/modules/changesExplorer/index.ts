import * as vscode from 'vscode';
import * as fs from 'fs';
import { registerCommand } from '../../host';
import logger from '../../logger';
import {
  COMMAND_CHANGES_REFRESH,
  COMMAND_CHANGES_UPLOAD_ALL,
  COMMAND_CHANGES_UPLOAD_FILE,
  COMMAND_CHANGES_TOGGLE_SCOPE,
} from '../../constants';
import { uploadFile, renameRemote, removeRemote } from '../../fileHandlers';
import { getFileService } from '../serviceManager';
import { getGitService, Change, Status } from '../git';
import ChangesTreeDataProvider, { ChangeNode } from './treeDataProvider';

// apply a set of git changes to the remote (create/upload/rename/delete)
async function uploadChanges(changes: Change[]) {
  const creates: Change[] = [];
  const uploads: Change[] = [];
  const renames: Change[] = [];
  const deletes: Change[] = [];

  for (const change of changes) {
    if (!getFileService(change.uri)) {
      continue;
    }
    // never recurse a submodule/directory through the single-file upload path
    try {
      if (fs.statSync(change.uri.fsPath).isDirectory()) {
        continue;
      }
    } catch (e) {
      /* deleted file: doesn't exist locally, handled below */
    }
    switch (change.status) {
      case Status.INDEX_MODIFIED:
      case Status.MODIFIED:
        uploads.push(change);
        break;
      case Status.INDEX_ADDED:
      case Status.UNTRACKED:
        creates.push(change);
        break;
      case Status.INDEX_RENAMED:
        renames.push(change);
        break;
      case Status.INDEX_DELETED:
      case Status.DELETED:
        deletes.push(change);
        break;
      default:
        break;
    }
  }

  await Promise.all(
    creates
      .concat(uploads)
      .map(c => uploadFile(c.uri).catch(e => logger.error('Upload failed.', e)))
  );
  await Promise.all(
    renames.map(c =>
      renameRemote(c.originalUri, { originPath: c.renameUri!.fsPath }).catch(e =>
        logger.error('Rename failed.', e)
      )
    )
  );
  await Promise.all(
    deletes.map(c => removeRemote(c.uri).catch(e => logger.error('Deletion failed.', e)))
  );
}

export default class ChangesExplorer {
  private _provider: ChangesTreeDataProvider;
  private _view: vscode.TreeView<ChangeNode>;

  constructor(context: vscode.ExtensionContext) {
    this._provider = new ChangesTreeDataProvider();
    this._view = vscode.window.createTreeView('sftpChanges', {
      treeDataProvider: this._provider,
    });
    context.subscriptions.push(this._view);

    registerCommand(context, COMMAND_CHANGES_REFRESH, () => this._provider.refresh());
    registerCommand(context, COMMAND_CHANGES_UPLOAD_ALL, () => this._uploadAll());
    registerCommand(context, COMMAND_CHANGES_UPLOAD_FILE, (node: ChangeNode) =>
      this._uploadNode(node)
    );
    registerCommand(context, COMMAND_CHANGES_TOGGLE_SCOPE, () => this._toggleScope());

    this._updateMessage();
    this._watchGit(context);
  }

  refresh() {
    this._provider.refresh();
  }

  private _toggleScope() {
    this._provider.scope =
      this._provider.scope === 'workingTree' ? 'branch' : 'workingTree';
    this._updateMessage();
    this._provider.refresh();
  }

  private _updateMessage() {
    this._view.message =
      this._provider.scope === 'branch'
        ? 'Scope: current branch (vs main/master) — toggle in the title bar'
        : 'Scope: working tree (uncommitted) — toggle in the title bar';
  }

  // refresh the view whenever git status changes (e.g. after a save)
  private _watchGit(context: vscode.ExtensionContext) {
    let git: any;
    try {
      git = getGitService();
    } catch (e) {
      return;
    }
    if (!git) {
      return;
    }
    const hook = () => this._provider.refresh();
    git.repositories.forEach((repo: any) =>
      context.subscriptions.push(repo.state.onDidChange(hook))
    );
    context.subscriptions.push(
      git.onDidOpenRepository((repo: any) => {
        context.subscriptions.push(repo.state.onDidChange(hook));
        hook();
      })
    );
  }

  private async _uploadAll() {
    const all = await this._provider.getFlatChanges();
    if (all.length === 0) {
      vscode.window.showInformationMessage('SFTP: no changed files to upload.');
      return;
    }
    await uploadChanges(all);
    this._provider.refresh();
  }

  private async _uploadNode(node: ChangeNode) {
    if (node && node.kind === 'file') {
      await uploadChanges([node.change]);
    } else if (node && node.kind === 'context') {
      await uploadChanges(node.changes);
    }
    this._provider.refresh();
  }
}
