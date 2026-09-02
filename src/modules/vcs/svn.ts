import * as path from 'path';
import * as fse from 'fs-extra';
import { execFile } from 'child_process';
import { Uri } from 'vscode';
import { VcsChange } from './types';
import { parseSvnStatusXml, toSvnChanges } from './svnStatusParser';

const MAX_OUTPUT_BUFFER = 64 * 1024 * 1024;

// Walk up from "dir" until a ".svn" folder is found (svn >= 1.7 keeps a single one at the root).
export async function findSvnRoot(dir: string): Promise<string | undefined> {
  let current = path.resolve(dir);
  while (true) {
    if (await fse.pathExists(path.join(current, '.svn'))) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return undefined;
    }
    current = parent;
  }
}

function runSvnStatus(cwd: string, target: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    execFile(
      'svn',
      ['status', '--xml', '--non-interactive', target],
      { cwd, maxBuffer: MAX_OUTPUT_BUFFER },
      (error, stdout, stderr) => {
        if (error) {
          if ((error as any).code === 'ENOENT') {
            reject(
              new Error(
                'Command "svn" not found. Install Subversion and make sure it is on your PATH.'
              )
            );
          } else {
            const detail = String(stderr || error.message || '').trim();
            reject(new Error(`"svn status" failed for ${target}: ${detail}`));
          }
          return;
        }
        resolve(String(stdout));
      }
    );
  });
}

// Changes below "baseDir" of the working copy rooted at "root".
export async function getSvnChanges(baseDir: string, root: string): Promise<VcsChange[]> {
  const xml = await runSvnStatus(baseDir, baseDir);
  return toSvnChanges(parseSvnStatusXml(xml)).map(
    (change): VcsChange => ({
      vcs: 'svn',
      kind: change.kind,
      uri: Uri.file(path.resolve(baseDir, change.path)),
      originalUri: change.originalPath
        ? Uri.file(path.resolve(baseDir, change.originalPath))
        : undefined,
      repositoryRoot: root,
    })
  );
}
