import * as vscode from 'vscode';
import * as path from 'path';
import {
  COMMAND_DIFF_ACTIVEFILE,
  COMMAND_DOWNLOAD_ACTIVEFILE,
} from '../constants';
import { toRemotePath } from '../helper';
import { getFileService } from './serviceManager';

// Passive + proactive awareness of the open file's remote version:
//  - status bar shows newer/older/same vs your local copy (showRemoteFreshness)
//  - with remoteWatchInterval > 0 it polls and toasts the moment the remote
//    changes under you (another user pushed while you were editing)
const FRESHNESS_ACTION = 'sftp.freshnessAction';
const TOLERANCE = 2; // seconds; absorb clock skew / mtime rounding

let item: vscode.StatusBarItem;
let timer: any = null;
const lastCategory = new Map<string, string>();

interface Freshness {
  cat: string; // remote-newer | local-newer | in-sync | no-remote | hidden
  localPath: string;
}

async function computeFreshness(
  editor: vscode.TextEditor | undefined
): Promise<Freshness | null> {
  if (!editor || editor.document.uri.scheme !== 'file') {
    return null;
  }
  const service = getFileService(editor.document.uri);
  if (!service) {
    return null;
  }
  let config: any;
  try {
    config = service.getConfig();
  } catch (e) {
    return null;
  }

  const localPath = editor.document.uri.fsPath;
  if (!config.showRemoteFreshness && !(config.remoteWatchInterval > 0)) {
    return { cat: 'hidden', localPath };
  }

  const remotePath = toRemotePath(localPath, service.baseDir, config.remotePath);
  try {
    const remoteFs = await service.getRemoteFileSystem(config);
    const localFs = service.getLocalFileSystem();
    const [remoteStat, localStat] = await Promise.all([
      remoteFs.lstat(remotePath),
      localFs.lstat(localPath),
    ]);
    const diff = remoteStat.mtime - localStat.mtime;
    const cat = diff > TOLERANCE ? 'remote-newer' : diff < -TOLERANCE ? 'local-newer' : 'in-sync';
    return { cat, localPath };
  } catch (e) {
    return { cat: 'no-remote', localPath };
  }
}

function render(cat: string) {
  switch (cat) {
    case 'remote-newer':
      item.text = '$(cloud-download) remote newer';
      item.tooltip = 'The remote version is newer — another user may have edited it. Click for actions.';
      item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
      break;
    case 'local-newer':
      item.text = '$(cloud-upload) local newer';
      item.tooltip = 'Your local copy is newer than the remote. Click to diff.';
      item.backgroundColor = undefined;
      break;
    case 'in-sync':
      item.text = '$(check) in sync';
      item.tooltip = 'Local and remote are in sync. Click to diff.';
      item.backgroundColor = undefined;
      break;
    case 'no-remote':
      item.text = '$(cloud) no remote';
      item.tooltip = 'No remote version found for this file.';
      item.backgroundColor = undefined;
      break;
    default:
      item.hide();
      return;
  }
  item.show();
}

function notifyRemoteChanged(localPath: string) {
  vscode.window
    .showWarningMessage(
      `Remote changed: "${path.basename(localPath)}" was just updated on the server.`,
      'Show Diff',
      'Download'
    )
    .then(choice => {
      if (choice === 'Show Diff') {
        vscode.commands.executeCommand(COMMAND_DIFF_ACTIVEFILE);
      } else if (choice === 'Download') {
        vscode.commands.executeCommand(COMMAND_DOWNLOAD_ACTIVEFILE);
      }
    });
}

async function refresh(fromPoll: boolean) {
  const res = await computeFreshness(vscode.window.activeTextEditor);
  if (!res) {
    item.hide();
    return;
  }
  render(res.cat);
  if (res.cat === 'hidden') {
    return;
  }
  const prev = lastCategory.get(res.localPath);
  // only toast on a background poll when it newly becomes stale
  if (fromPoll && res.cat === 'remote-newer' && prev !== 'remote-newer') {
    notifyRemoteChanged(res.localPath);
  }
  lastCategory.set(res.localPath, res.cat);
}

function resetTimer(intervalSec: number) {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  if (intervalSec > 0) {
    timer = setInterval(() => refresh(true), intervalSec * 1000);
  }
}

async function onActiveEditorChange() {
  await refresh(false);
  let interval = 0;
  const editor = vscode.window.activeTextEditor;
  if (editor && editor.document.uri.scheme === 'file') {
    const service = getFileService(editor.document.uri);
    if (service) {
      try {
        interval = service.getConfig().remoteWatchInterval || 0;
      } catch (e) {
        /* ignore */
      }
    }
  }
  resetTimer(interval);
}

// status bar click: offer actions based on the current freshness
async function freshnessAction() {
  const res = await computeFreshness(vscode.window.activeTextEditor);
  if (!res || res.cat === 'hidden') {
    return;
  }
  if (res.cat === 'remote-newer') {
    const pick = await vscode.window.showQuickPick(
      [
        { label: '$(cloud-download) Download latest version', id: 'download' },
        { label: '$(diff) Show diff', id: 'diff' },
        { label: '$(x) Dismiss', id: 'dismiss' },
      ],
      { placeHolder: 'The remote version is newer than your local copy' }
    );
    if (!pick || pick.id === 'dismiss') {
      return;
    }
    vscode.commands.executeCommand(
      pick.id === 'download' ? COMMAND_DOWNLOAD_ACTIVEFILE : COMMAND_DIFF_ACTIVEFILE
    );
  } else {
    vscode.commands.executeCommand(COMMAND_DIFF_ACTIVEFILE);
  }
}

export function init(context: vscode.ExtensionContext) {
  item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
  item.command = FRESHNESS_ACTION;
  context.subscriptions.push(item);
  context.subscriptions.push(
    vscode.commands.registerCommand(FRESHNESS_ACTION, freshnessAction)
  );
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(() => onActiveEditorChange())
  );
  context.subscriptions.push({
    dispose: () => {
      if (timer) {
        clearInterval(timer);
      }
    },
  });
  onActiveEditorChange();
}
