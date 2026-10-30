import * as vscode from 'vscode';
import * as path from 'path';
import { GitExtension, API, Status, Change, Repository } from './git';

let git: API;

export { API as GitAPI, Repository, Status, Change };

export function getGitService(): API {
  const gitExtension = vscode.extensions.getExtension<GitExtension>('vscode.git')!.exports;

  git = gitExtension.getAPI(1);
  return git;
}

export async function getRepository(git: API): Promise<Repository | undefined> {
  if (git.repositories.length === 1) {
    return git.repositories[0];
  }

  if (git.repositories.length === 0) {
    throw new Error('There are no available repositories');
  }

  const picks = git.repositories.map(repo => {
    const label = path.basename(repo.rootUri.fsPath);
    const description = repo.state.HEAD ? repo.state.HEAD.name : '';

    return {
      label,
      description,
      repository: repo,
    };
  });

  const pick = await vscode.window.showQuickPick(picks, { placeHolder: 'Choose a repository' });

  return pick && pick.repository;
}
