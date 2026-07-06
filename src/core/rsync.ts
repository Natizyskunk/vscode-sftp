import * as vscode from 'vscode';
import { execFile } from 'child_process';
import upath from './upath';
import logger from '../logger';

let rsyncChecked = false;

// Proactive check: warn as soon as a context that uses rsync is loaded (instead of
// only failing on the first upload). Runs at most once per session.
export function warnIfRsyncMissing() {
  if (rsyncChecked) {
    return;
  }
  rsyncChecked = true;
  execFile('rsync', ['--version'], (error: any) => {
    if (error && error.code === 'ENOENT') {
      vscode.window.showWarningMessage(rsyncNotFoundMessage());
    }
  });
}

function shouldUseAgent(config: any): boolean {
  return typeof config.agent === 'string' && config.agent.length > 0;
}

function shouldUseKey(config: any): boolean {
  return typeof config.privateKeyPath === 'string' && config.privateKeyPath.length > 0;
}

// Build the `rsync -e` transport string (system ssh with the context's key/port).
function buildSshCommand(config: any): string {
  let ssh = `ssh -p ${config.port}`;
  if (shouldUseKey(config)) {
    ssh += ` -i "${config.privateKeyPath}"`;
  }
  if (config.sshConfigPath) {
    ssh += ` -F "${config.sshConfigPath}"`;
  }
  return ssh;
}

/**
 * Upload a file or directory with the local `rsync` binary over SSH.
 * Used when the server restricts the SFTP subsystem but allows shell/rsync
 * (rsync runs over an exec channel, like a normal login shell).
 */
export function rsyncUpload(
  config: any,
  localPath: string,
  remotePath: string,
  isDir: boolean
): Promise<void> {
  // viability guards -> clear errors instead of a cryptic SFTP failure
  if (config.hop) {
    return Promise.reject(
      new Error('rsync upload mode does not support connection hopping (hop).')
    );
  }
  if (!shouldUseKey(config) && !shouldUseAgent(config)) {
    return Promise.reject(
      new Error(
        'rsync upload mode requires an SSH key (privateKeyPath) or ssh-agent ' +
          '(password auth would need sshpass, which is not bundled).'
      )
    );
  }

  const sshCmd = buildSshCommand(config);
  const remoteDir = isDir ? remotePath : upath.dirname(remotePath);
  // create the remote dir if missing, then run rsync (works on old rsync too)
  const rsyncPath = `mkdir -p "${remoteDir}" && rsync`;

  const src = isDir ? localPath.replace(/\/?$/, '/') : localPath;
  const remoteSpec = `${config.username}@${config.host}:${isDir ? remotePath.replace(/\/?$/, '/') : remotePath}`;

  const args = ['-rt', '-e', sshCmd, `--rsync-path=${rsyncPath}`, src, remoteSpec];

  // info log stays clean (no username / key path); full command only at debug level
  logger.info(`rsync upload ➞ ${config.host}:${remotePath}`);
  logger.debug(
    `rsync ${args.map(a => (a.indexOf(' ') !== -1 ? `'${a}'` : a)).join(' ')}`
  );

  return new Promise<void>((resolve, reject) => {
    execFile('rsync', args, (error: any, _stdout, stderr) => {
      if (error) {
        if (error.code === 'ENOENT') {
          reject(new Error(rsyncNotFoundMessage()));
          return;
        }
        reject(new Error(stderr ? stderr.trim() : error.message));
        return;
      }
      resolve();
    });
  });
}

function rsyncNotFoundMessage(): string {
  let hint: string;
  switch (process.platform) {
    case 'darwin':
      hint = 'macOS: usually preinstalled; otherwise `brew install rsync`.';
      break;
    case 'win32':
      hint =
        'Windows: install rsync via WSL, Git Bash, MSYS2 or `choco install rsync`, ' +
        'and make sure it is on your PATH.';
      break;
    default:
      hint = 'Linux: `sudo apt install rsync` (Debian/Ubuntu) or `sudo yum install rsync`.';
      break;
  }
  return (
    '`rsync` was not found on your machine, but this context uses "uploadMethod": "rsync". ' +
    'Install rsync (or switch back to the default SFTP upload). ' +
    hint
  );
}
