import * as vscode from 'vscode';
import * as fse from 'fs-extra';
import * as os from 'os';
import * as path from 'path';
import { execFile } from 'child_process';
import { COMMAND_UPLOAD_COMMITFILES } from '../constants';
import { getFileService } from '../modules/serviceManager';
import { uploadFile, removeRemote } from '../fileHandlers';
import { getGitService, getRepository } from '../modules/git';
import { checkCommand } from './abstract/createCommand';
import logger from '../logger';
import { simplifyPath } from '../helper';

const MAX_COMMITS = 50;

interface CommitInfo {
  hash: string;
  shortHash: string;
  subject: string;
  author: string;
  relativeDate: string;
  parents: string[];
}

interface CommitChange {
  // Path relative to the repository root, with forward slashes.
  path: string;
  uri: vscode.Uri;
  deleted: boolean;
}

export default checkCommand({
  id: COMMAND_UPLOAD_COMMITFILES,

  async handleCommand(commitHash?: string) {
    const git = getGitService();
    const repository = await getRepository(git);
    if (!repository) {
      return;
    }

    const gitPath = git.git.path;
    const cwd = repository.rootUri.fsPath;

    const commit = typeof commitHash === 'string'
      ? await getCommit(gitPath, cwd, commitHash)
      : await pickBranchAndCommit(gitPath, cwd);
    if (!commit) {
      return;
    }

    const changes = (await getCommitChanges(gitPath, cwd, commit)).filter(change =>
      getFileService(change.uri)
    );
    const uploads = changes.filter(change => !change.deleted);
    const deletes = changes.filter(change => change.deleted);

    if (changes.length === 0) {
      vscode.window.showInformationMessage(`No files to upload for commit ${commit.shortHash}.`);
      return;
    }

    if (deletes.length > 0) {
      const answer = await vscode.window.showWarningMessage(
        `Commit ${commit.shortHash} deletes ${deletes.length} file(s). They will also be deleted from the remote. Continue?`,
        { modal: true },
        'Continue'
      );
      if (answer !== 'Continue') {
        return;
      }
    }

    // Upload the files as they are in the commit, not the (possibly modified) working tree copies.
    const tmpDir = fse.mkdtempSync(path.join(os.tmpdir(), 'vscode-sftp-commit-'));
    const failed: string[] = [];
    try {
      const extracted: { change: CommitChange; srcFsPath: string }[] = [];
      for (const change of uploads) {
        try {
          // --filters applies the same conversions as a checkout (e.g. core.autocrlf line endings).
          const content = await runGitBuffer(gitPath, cwd, [
            'cat-file',
            '--filters',
            `${commit.hash}:${change.path}`,
          ]);
          const srcFsPath = path.join(tmpDir, change.path);
          await fse.outputFile(srcFsPath, content);
          extracted.push({ change, srcFsPath });
        } catch (e) {
          failed.push(change.uri.fsPath);
          logger.error('Reading file from commit failed.', e);
        }
      }

      await Promise.all(
        extracted.map(async ({ change, srcFsPath }) => {
          try {
            await uploadFile(change.uri, { srcFsPath });
          } catch (e) {
            failed.push(change.uri.fsPath);
            logger.error('Upload failed.', e);
          }
        })
      );
    } finally {
      await fse.remove(tmpDir);
    }

    await Promise.all(
      deletes.map(async change => {
        try {
          await removeRemote(change.uri);
        } catch (e) {
          failed.push(change.uri.fsPath);
          logger.error('Deletion failed.', e);
        }
      })
    );

    logger.log('');
    logger.log(`------ Upload Commit Files Result (${commit.shortHash} ${commit.subject}) ------`);
    outputGroup('upload', uploads);
    outputGroup('deleted', deletes);

    if (failed.length > 0) {
      vscode.window.showErrorMessage(
        `Commit ${commit.shortHash}: ${failed.length} file(s) failed. See the SFTP output for details.`
      );
    } else {
      vscode.window.showInformationMessage(
        `Commit ${commit.shortHash}: ${uploads.length} file(s) uploaded, ${deletes.length} deleted.`
      );
    }
  },
});

function runGitBuffer(gitPath: string, cwd: string, args: string[]): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    execFile(
      gitPath,
      args,
      { cwd, encoding: 'buffer', maxBuffer: 512 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          reject(new Error(stderr.toString() || error.message));
          return;
        }
        resolve(stdout);
      }
    );
  });
}

async function runGit(gitPath: string, cwd: string, args: string[]): Promise<string> {
  return (await runGitBuffer(gitPath, cwd, args)).toString('utf8');
}

const LOG_FORMAT = '--format=%H%x1f%h%x1f%s%x1f%an%x1f%ar%x1f%P%x1e';

function parseLog(output: string): CommitInfo[] {
  return output
    .split('\x1e')
    .map(record => record.trim())
    .filter(Boolean)
    .map(record => {
      const [hash, shortHash, subject, author, relativeDate, parents] = record.split('\x1f');
      return {
        hash,
        shortHash,
        subject,
        author,
        relativeDate,
        parents: parents ? parents.split(' ') : [],
      };
    });
}

async function getCommit(gitPath: string, cwd: string, ref: string): Promise<CommitInfo | undefined> {
  const output = await runGit(gitPath, cwd, ['log', '-1', LOG_FORMAT, ref, '--']);
  return parseLog(output)[0];
}

async function pickBranchAndCommit(gitPath: string, cwd: string): Promise<CommitInfo | undefined> {
  const ref = await pickBranch(gitPath, cwd);
  return ref ? pickCommit(gitPath, cwd, ref) : undefined;
}

async function pickBranch(gitPath: string, cwd: string): Promise<string | undefined> {
  const current = (await runGit(gitPath, cwd, ['rev-parse', '--abbrev-ref', 'HEAD'])).trim();
  const output = await runGit(gitPath, cwd, [
    'for-each-ref',
    '--sort=-committerdate',
    '--format=%(refname)%1f%(refname:short)%1f%(committerdate:relative)%1f%(subject)',
    'refs/heads',
    'refs/remotes',
  ]);

  const branches = output
    .split('\n')
    .filter(Boolean)
    .map(line => line.split('\x1f'))
    // Skip symbolic refs like refs/remotes/origin/HEAD.
    .filter(([refname]) => !refname.endsWith('/HEAD'))
    .map(([, name, relativeDate, subject]) => ({ name, relativeDate, subject }));

  // The current branch always comes first so the usual case is just pressing Enter.
  const currentRef = current === 'HEAD' ? 'HEAD' : current;
  const others = branches.filter(branch => branch.name !== current);
  if (others.length === 0) {
    return currentRef;
  }

  const picks = [
    {
      label: `$(git-branch) ${current === 'HEAD' ? 'HEAD (detached)' : current}`,
      description: 'current',
      ref: currentRef,
    },
    ...others.map(branch => ({
      label: `$(git-branch) ${branch.name}`,
      description: branch.relativeDate,
      detail: branch.subject,
      ref: branch.name,
    })),
  ];

  const pick = await vscode.window.showQuickPick(picks, {
    placeHolder: 'Choose a branch',
    matchOnDescription: true,
  });

  return pick && pick.ref;
}

async function pickCommit(gitPath: string, cwd: string, ref: string): Promise<CommitInfo | undefined> {
  const output = await runGit(gitPath, cwd, ['log', `-${MAX_COMMITS}`, LOG_FORMAT, ref, '--']);
  const picks = parseLog(output).map(commit => ({
    label: commit.subject,
    description: commit.shortHash,
    detail: `${commit.author}, ${commit.relativeDate}`,
    commit,
  }));

  const pick = await vscode.window.showQuickPick(picks, {
    placeHolder: `Choose a commit of ${ref} to upload its files`,
    matchOnDescription: true,
    matchOnDetail: true,
  });

  return pick && pick.commit;
}

async function getCommitChanges(
  gitPath: string,
  cwd: string,
  commit: CommitInfo
): Promise<CommitChange[]> {
  // Merge commits are compared against their first parent, root commits against the empty tree.
  const args = ['diff-tree', '-r', '--no-commit-id', '--name-status', '-z', '--no-renames'];
  if (commit.parents.length > 1) {
    args.push(commit.parents[0], commit.hash);
  } else {
    args.push('--root', commit.hash);
  }

  const fields = (await runGit(gitPath, cwd, args)).split('\0').filter(Boolean);
  const changes: CommitChange[] = [];
  for (let i = 0; i + 1 < fields.length; i += 2) {
    const status = fields[i];
    const filePath = fields[i + 1];
    changes.push({
      path: filePath,
      uri: vscode.Uri.file(path.join(cwd, filePath)),
      deleted: status === 'D',
    });
  }

  return changes;
}

function outputGroup(label: string, items: CommitChange[]) {
  if (items.length <= 0) {
    return;
  }

  logger.log(`${label.toUpperCase()}:`);
  logger.log(items.map(change => simplifyPath(change.uri.fsPath)).join('\n'));
  logger.log('');
}
